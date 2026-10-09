// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"paguro.dev/paguro/internal/shield"
)

// netnsWatcher closes the last RST window of a migration.
//
// Measured (pcap on the client node): a client retransmit reached the target
// 120 ms *before* the restore wrapper raised the shield. In that window CNI
// ADD had already given the new sandbox the old pod IP, but runc had not yet
// created the pause container – the wrapper's earliest hook. The kernel had no
// socket for the segment and answered with RST; the connection was gone.
//
// containerd creates the sandbox network namespace (/var/run/netns/cni-*)
// before it calls CNI ADD. While a migration targets this node, the agent
// watches that directory with inotify and raises the shield in every new
// namespace within milliseconds – long before any CNI can make the IP
// reachable (Cilium needs >= 80 ms to build the endpoint). This is
// independent of the CNI plugin.
//
// Namespaces of unrelated pods that happen to be created in the same window
// are released as soon as they carry an IP other than the migrated one; until
// then their pods have no running containers anyway.
//
// containerd creates the /run/netns entry as an empty file – that is the
// inotify event – and bind-mounts the namespace onto it afterwards. Entering
// it in between fails (setns: EINVAL). On a node, 148 of 200 entries were
// still plain files when the event arrived, and nsenter right after the event
// failed 2 times in 200; the watcher used to drop such a failure silently,
// and a sandbox that got the old IP stayed unshielded (lab: one client RST,
// cross-node migration over 1 GbE). It now waits for the mount and retries.
type netnsWatcher struct {
	h     *Host
	oldIP string
	log   interface {
		Info(string, ...any)
		Warn(string, ...any)
	}
}

// nsfsMagic is NSFS_MAGIC, the file system of a mounted namespace.
const nsfsMagic = 0x6e736673

// netnsMountWait bounds the wait for containerd's bind mount (microseconds
// to milliseconds in practice).
const netnsMountWait = 2 * time.Second

// awaitNetnsMount waits until path is a mounted namespace. An error means the
// entry is gone (failed sandbox) or never became a namespace.
func awaitNetnsMount(ctx context.Context, path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		var st unix.Statfs_t
		if err := unix.Statfs(path, &st); err != nil {
			return err
		}
		if st.Type == nsfsMagic {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s is not a namespace after %s", path, timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Millisecond):
		}
	}
}

// hostNetnsDir is /run/netns, not /var/run/netns: on the host /var/run is an
// absolute symlink to /run, which – resolved through /proc/1/root – would
// point into the agent container's own /run.
const hostNetnsDir = "/run/netns"

// watchNetns runs until ctx is cancelled.
func (a *Agent) watchNetns(ctx context.Context, oldIP string, log interface {
	Info(string, ...any)
	Warn(string, ...any)
}) error {
	dir := a.Host.Path(hostNetnsDir)
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if _, err := unix.InotifyAddWatch(fd, dir, unix.IN_CREATE|unix.IN_MOVED_TO); err != nil {
		return fmt.Errorf("inotify on %s: %w", dir, err)
	}
	w := &netnsWatcher{h: a.Host, oldIP: oldIP, log: log}
	buf := make([]byte, 64*1024)
	pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	for {
		if ctx.Err() != nil {
			return nil
		}
		// poll wakes up at once on an event (far below the >= 80 ms a CNI
		// needs to make an IP reachable); the timeout only bounds how late
		// a cancellation is noticed.
		if _, err := unix.Poll(pfd, 100); err != nil && err != unix.EINTR {
			return err
		}
		n, err := unix.Read(fd, buf)
		if err == unix.EAGAIN || err == unix.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		for off := 0; off+unix.SizeofInotifyEvent <= n; {
			ev := (*unix.InotifyEvent)(unsafePointer(&buf[off]))
			nameBytes := buf[off+unix.SizeofInotifyEvent : off+unix.SizeofInotifyEvent+int(ev.Len)]
			name := strings.TrimRight(string(nameBytes), "\x00")
			off += unix.SizeofInotifyEvent + int(ev.Len)
			if name == "" || !strings.HasPrefix(name, "cni-") {
				continue
			}
			go w.shieldNew(ctx, filepath.Join(hostNetnsDir, name))
		}
	}
}

func (w *netnsWatcher) shieldNew(ctx context.Context, path string) {
	start := time.Now()
	if err := awaitNetnsMount(ctx, w.h.Path(path), netnsMountWait); err != nil {
		if !os.IsNotExist(err) && ctx.Err() == nil {
			w.log.Warn("new sandbox namespace not shielded", "netns", path, "err", err)
		}
		return // gone: a failed sandbox
	}
	mounted := time.Since(start)
	run := w.h.ShieldRunner(ctx)
	var err error
	for attempt := 0; attempt < 5; attempt++ {
		if err = shield.Raise(run, path); err == nil {
			break
		}
		if _, serr := os.Stat(w.h.Path(path)); serr != nil {
			return // the namespace was removed (failed CNI ADD)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		w.log.Warn("new sandbox namespace not shielded", "netns", path, "err", err)
		return
	}
	w.log.Info("shield raised in new sandbox namespace before CNI", "netns", path,
		"ms", ms(time.Since(start)), "mountWaitMs", ms(mounted))

	// Release namespaces of unrelated pods: poll the namespace's IPv4
	// addresses until CNI has assigned one.
	for i := 0; i < 200; i++ {
		out, err := w.h.Run(ctx, nil, "nsenter", "--net="+path, "ip", "-4", "-o", "addr", "show", "scope", "global")
		if err != nil {
			return // namespace removed
		}
		addrs := string(out)
		if strings.Contains(addrs, " inet ") {
			if !strings.Contains(addrs, " "+w.oldIP+"/") {
				_ = shield.Lower(run, path)
				w.log.Info("shield removed again: namespace belongs to another pod", "netns", path)
			}
			// Our namespace: the restore wrapper lowers the shield after the
			// last container is restored.
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func unsafePointer(b *byte) unsafe.Pointer { return unsafe.Pointer(b) }
