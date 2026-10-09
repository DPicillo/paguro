// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

// The restore of an app container on the target (restoreContainer) and
// what it needs: checkpoint, deltas, old addresses, lazy pages, the shield.

package main

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"paguro.dev/paguro/internal/archive"
	"paguro.dev/paguro/internal/criuimg"
	"paguro.dev/paguro/internal/criulog"
	"paguro.dev/paguro/internal/layout"
	"paguro.dev/paguro/internal/ocispec"
	"paguro.dev/paguro/internal/shield"
	"paguro.dev/paguro/pkg/names"
)

// restoreContainer turns the create of an app container into a restore
// from its checkpoint. Every step either goes on or ends in a cold start
// (restorer.cold): the workload runs either way, with or without its state.
func restoreContainer(inv invocation, spec *ocispec.Spec, uid string) int {
	r := newRestorer(inv, spec, uid)

	// A checkpoint is consumed exactly once. If this container was already
	// restored (or cold-started) for this migration, a new create means the
	// container exited and kubelet restarts it: start it fresh, exactly as
	// Kubernetes would without Paguro. Restoring again would bring back a
	// stale memory state and replay TCP connections that no longer exist
	// (observed: a restarted container was restored from the same checkpoint
	// a second time). The pod's own shield is not touched.
	if layout.Exists(filepath.Join(r.dir, names.FileRestored)) || layout.Exists(filepath.Join(r.dir, names.FileColdStart)) {
		logf("container %s (%s): checkpoint already consumed – normal start (container restart)", r.name, inv.id)
		return runRunc(inv.global, "create", inv.cmdArgs, inv.id, inv.preserveFDs)
	}
	logf("container %s (%s): restore from %s", r.name, inv.id, r.dir)

	switch err := r.waitForCheckpoint(); {
	case errors.Is(err, errRolledBack):
		// Rolled back before the commit: the source runs on. Neither
		// restore nor cold start – a second copy must never run. The failed
		// create lets kubelet delete the pod at once.
		logf("container %s: migration rolled back before its commit – not starting", r.name)
		fmt.Fprintf(os.Stderr, "paguro-runc: migration %s was rolled back before its commit; this replacement must not start\n", uid)
		return 1
	case err != nil:
		return r.cold(err.Error())
	}
	meta, cm, err := r.containerMeta()
	if err != nil {
		return r.cold(err.Error())
	}
	if err := r.applyDeltas(); err != nil {
		return r.cold(err.Error())
	}
	socks, err := criuimg.ListSockets(r.finalDir())
	if err != nil {
		logf("container %s: sockets of the checkpoint: %v", r.name, err)
	}
	addrs, err := r.addOldAddresses(meta, socks.Addrs)
	if err != nil {
		return r.cold(err.Error())
	}
	r.holdUDPServers(socks.UDPServerPorts)
	if err := r.prepareImages(cm); err != nil {
		return r.cold(err.Error())
	}
	work := filepath.Join(r.dir, "work-"+inv.id)
	_ = os.MkdirAll(work, 0o700)
	rargs := restoreArgs(inv.cmdArgs, cm.Opts, r.finalDir(), work)
	lazyUnit := ""
	if cm.LazyPages {
		lazyUnit = r.startLazy(work)
		if lazyUnit != "" {
			rargs = append(rargs, "--lazy-pages")
		}
	}
	err = r.runRestore(rargs, work, lazyUnit)
	if err != nil && lazyUnit != "" && eagerMayHelp(err) {
		err = r.restoreEagerly(cm.Opts, err)
	}
	if err != nil {
		return r.cold(err.Error())
	}
	r.finish(addrs)
	return 0
}

// eagerMayHelp: a lazy restore failed where pages are mapped or checked –
// the restorer's vDSO check ("vdso: Invalid ELF magic", seen on EKS in
// GitLab's runit processes after many pre-copy rounds, not reproduced in a
// small pod) or userfaultfd itself. An eager restore takes another path
// there; the images are the same.
func eagerMayHelp(err error) bool {
	s, _, _ := strings.Cut(err.Error(), " (log: ") // CRIU's words, not the path
	return strings.Contains(s, "vdso") || strings.Contains(s, "uffd") || strings.Contains(s, "userfaultfd") ||
		strings.Contains(s, "lazy")
}

// restoreEagerly tries the restore once more, without lazy pages, before
// the cold start: the restore failed after the commit, so the alternative
// is the loss of the memory state. The shield still drops the pod's TCP
// packets, so the failed attempt's sockets told the peers nothing. lazyErr
// is the first attempt's error, reported if this one fails too.
func (r *restorer) restoreEagerly(opts layout.DumpOptions, lazyErr error) error {
	logf("container %s: lazy restore failed (%v) – trying once more without lazy pages", r.name, lazyErr)
	_ = os.Rename(filepath.Join(r.dir, "restore-failed.log"), filepath.Join(r.dir, "restore-failed-lazy.log"))
	removeCRIUNetworkLock(r.spec.NetNSPath())
	work := filepath.Join(r.dir, "work-"+r.inv.id+"-eager")
	_ = os.RemoveAll(work)
	_ = os.MkdirAll(work, 0o700)
	if err := r.runRestore(restoreArgs(r.inv.cmdArgs, opts, r.finalDir(), work), work, ""); err != nil {
		return fmt.Errorf("lazy: %v; eager: %w", lazyErr, err)
	}
	logf("container %s: restored eagerly after the failed lazy restore", r.name)
	return nil
}

// restorer holds one container's restore (restoreContainer).
type restorer struct {
	inv       invocation
	spec      *ocispec.Spec
	uid, name string
	dir       string // the container's checkpoint directory
	res       layout.Restored
}

func newRestorer(inv invocation, spec *ocispec.Spec, uid string) *restorer {
	name := spec.Ann(ocispec.AnnContainerName)
	return &restorer{inv: inv, spec: spec, uid: uid, name: name, dir: layout.ContainerDir(uid, name),
		res: layout.Restored{ContainerID: inv.id, StartedAt: time.Now()}}
}

func (r *restorer) finalDir() string { return filepath.Join(layout.ImagesDir(r.uid, r.name), "final") }

// cold starts the container fresh and records why.
func (r *restorer) cold(reason string) int {
	logf("container %s: COLD START – %s", r.name, reason)
	r.res.Reason = reason
	r.res.FinishedAt = time.Now()
	_ = layout.WriteJSONAtomic(filepath.Join(r.dir, names.FileColdStart), r.res)
	removeCRIUNetworkLock(r.spec.NetNSPath())
	lowerShieldIfDone(r.uid, r.spec)
	return runRunc(r.inv.global, "create", r.inv.cmdArgs, r.inv.id, r.inv.preserveFDs)
}

// errRolledBack: the migration was rolled back before its commit.
var errRolledBack = errors.New("rolled back before the commit")

// readyPoll is how often the wrapper looks for READY: it usually arrives
// while the source is frozen, and every millisecond of polling delay is a
// millisecond of freeze.
const readyPoll = 2 * time.Millisecond

// waitForCheckpoint waits for READY – as long as data keeps arriving: a
// large pod's final images, or a transfer that a restarted source agent
// resumes, can take longer than waitForData in total. Only silence counts.
func (r *restorer) waitForCheckpoint() error {
	deadline := time.Now().Add(waitForData)
	nextLook := time.Now()
	for {
		if layout.Exists(filepath.Join(r.dir, names.FileReady)) {
			r.res.WaitMs = time.Since(r.res.StartedAt).Milliseconds()
			return nil
		}
		if aborted(r.uid) {
			return errRolledBack
		}
		if layout.Exists(filepath.Join(r.dir, names.FileFailed)) {
			b, _ := os.ReadFile(filepath.Join(r.dir, names.FileFailed))
			return errors.New("source reported an error: " + strings.TrimSpace(string(b)))
		}
		if now := time.Now(); now.After(nextLook) {
			nextLook = now.Add(time.Second)
			// The whole migration directory: emptyDirs arrive before the
			// images and can take long.
			if t := layout.LatestWrite(layout.Root(r.uid)); t.Add(waitForData).After(deadline) {
				deadline = t.Add(waitForData)
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("no data for %s", waitForData)
		}
		time.Sleep(readyPoll)
	}
}

// containerMeta reads the migration's metadata and this container's part.
func (r *restorer) containerMeta() (*layout.Meta, *layout.ContainerMeta, error) {
	meta, err := layout.ReadMeta(r.uid)
	if err != nil {
		return nil, nil, errors.New("meta.json: " + err.Error())
	}
	for i := range meta.Containers {
		if meta.Containers[i].Name == r.name {
			return meta, &meta.Containers[i], nil
		}
	}
	return nil, nil, errors.New("container missing from meta.json")
}

// applyDeltas applies the emptyDir contents (once per pod) and the rootfs
// delta.
func (r *restorer) applyDeltas() error {
	start := time.Now()
	if err := applyEmptyDirs(r.uid, r.spec); err != nil {
		return errors.New("emptyDir: " + err.Error())
	}
	if f, err := os.Open(filepath.Join(r.dir, names.FileRootfsDiff)); err == nil {
		st, err := archive.Unpack(f, r.spec.RootfsPath(), archive.UnpackOptions{Overlay: true})
		f.Close()
		if err != nil {
			return errors.New("rootfs delta: " + err.Error())
		}
		logf("container %s: rootfs delta: %d files, %d whiteouts, %d bytes", r.name, st.Files, st.Whiteouts, st.Bytes)
	}
	r.res.ApplyMs = time.Since(start).Milliseconds()
	return nil
}

// addOldAddresses: with a new pod IP the restored sockets are bound to the
// old address(es) (after chained migrations there can be several), so they
// must be local again before the restore. They go on lo, never on eth0,
// and the pod must not answer ARP for them (arp_ignore=1) nor use them as
// ARP source (arp_announce=2): with a bridge CNI (Flannel's cni0) the pod
// would otherwise take over traffic for its old IP – and conflict with a
// new pod that gets that IP. Phantom mode translates the restored
// connections on the wire; generic mode aborts them after the restore.
// Returns the addresses (from the metadata and the checkpoint's sockets).
func (r *restorer) addOldAddresses(meta *layout.Meta, inCheckpoint []netip.Addr) ([]string, error) {
	tcp := r.spec.Ann(names.AnnotationTCP)
	addrs := slices.Clone(meta.BoundIPs)
	if old := r.spec.Ann(names.AnnotationOldIP); old != "" && !slices.Contains(addrs, old) {
		addrs = append(addrs, old)
	}
	// The checkpoint names every address its sockets bind to, including
	// sockets that are bound but closed – a connection to an external
	// service that broke at an earlier migration – which sock_diag on the
	// source does not list on every kernel.
	for _, a := range inCheckpoint {
		if s := a.String(); !slices.Contains(addrs, s) {
			addrs = append(addrs, s)
		}
	}
	if (tcp != names.TCPClose && tcp != names.TCPTranslate) || r.spec.NetNSPath() == "" {
		return addrs, nil
	}
	ns := "--net=" + r.spec.NetNSPath()
	for _, kv := range []string{"net.ipv4.conf.all.arp_ignore=1", "net.ipv4.conf.all.arp_announce=2"} {
		if _, err := shield.Exec("", "nsenter", ns, "sysctl", "-q", "-w", kv); err != nil {
			return nil, fmt.Errorf("cannot set %s: %v", kv, err)
		}
	}
	for _, a := range addrs {
		prefix := a + "/32"
		if strings.Contains(a, ":") {
			prefix = a + "/128"
		}
		if _, err := shield.Exec("", "nsenter", ns, "ip", "addr", "add", prefix, "dev", "lo"); err != nil && !strings.Contains(err.Error(), "File exists") {
			// Without the address the restore of its sockets fails anyway.
			return nil, fmt.Errorf("cannot add old address %s: %v", a, err)
		}
	}
	if len(addrs) > 0 {
		logf("container %s: old addresses on lo: %v", r.name, addrs)
	}
	return addrs, nil
}

// holdUDPServers: with a new pod IP, the restored UDP servers answer a
// peer only once it has written to the new address, for a while (see
// shield.HoldUDPReplies). Without it the players of a game server behind a
// Service lose their session.
func (r *restorer) holdUDPServers(ports []uint16) {
	tcp := r.spec.Ann(names.AnnotationTCP)
	if (tcp != names.TCPClose && tcp != names.TCPTranslate) || len(ports) == 0 {
		return
	}
	if err := shield.HoldUDPReplies(shield.Exec, r.spec.NetNSPath(), r.name, ports, time.Now().Add(shield.UDPHoldWindow)); err != nil {
		logf("container %s: UDP servers not held, their peers may lose the session: %v", r.name, err)
		return
	}
	logf("container %s: UDP servers on %v answer only peers that wrote first, for %s", r.name, ports, shield.UDPHoldWindow)
}

// restoreArgs translates the create call's arguments into runc restore's.
func restoreArgs(createArgs []string, opts layout.DumpOptions, imageDir, workDir string) []string {
	rargs := []string{"--detach", "--image-path", imageDir, "--work-path", workDir}
	for i := 0; i < len(createArgs); i++ {
		a := createArgs[i]
		n, _, hasVal := strings.Cut(a, "=")
		switch n {
		case "--bundle", "-b", "--pid-file", "--console-socket":
			rargs = append(rargs, a)
			if !hasVal && i+1 < len(createArgs) {
				i++
				rargs = append(rargs, createArgs[i])
			}
		case "--no-pivot":
			rargs = append(rargs, a)
		case "--preserve-fds", "--pidfd-socket":
			if !hasVal {
				i++
			}
		}
	}
	if opts.TCPEstablished {
		// Always restore connections as they were. Generic mode aborts them
		// right after the restore (abortConnections). runc has no
		// --tcp-close, and passing it through org.criu.config would stick to
		// the container: runc keeps that annotation and the next checkpoint
		// of this container would silently drop its connections too.
		rargs = append(rargs, "--tcp-established")
	}
	if opts.FileLocks {
		rargs = append(rargs, "--file-locks")
	}
	if opts.ExtUnixSk {
		rargs = append(rargs, "--ext-unix-sk")
	}
	return rargs
}

// prepareImages points the final image at the compacted base of the
// pre-copy rounds – one flat parent instead of a deep, fragmented chain,
// faster for eager restores and the lazy-pages daemon – and, for a lazy
// restore, marks the parent pages lazy. If compaction ran but the base is
// incomplete, the original chain is gone: a restore would fail, so the
// error starts the container cold right away.
func (r *restorer) prepareImages(cm *layout.ContainerMeta) error {
	final := r.finalDir()
	if linked, err := criuimg.LinkFinalToBase(final, filepath.Join(layout.ImagesDir(r.uid, r.name), "base")); err != nil {
		return errors.New("pre-copy base image unusable: " + err.Error())
	} else if linked {
		logf("container %s: final image linked to the compacted base", r.name)
	}
	if !cm.LazyPages {
		return nil
	}
	// Pre-copy left most pages in parent images, which CRIU would restore
	// eagerly; mark them lazy too (see internal/criuimg).
	start := time.Now()
	st, err := criuimg.MakeParentPagesLazy(final)
	if err != nil {
		logf("container %s: cannot mark parent pages lazy, eager restore: %v", r.name, err)
		cm.LazyPages = false
		return nil
	}
	logf("container %s: %d parent pages marked lazy, %d stay eager, %d already lazy (%d ms)",
		r.name, st.LazyPages, st.EagerPages, st.AlreadyLazy, time.Since(start).Milliseconds())
	return nil
}

// startLazy starts the lazy-pages daemon and returns its systemd unit (""
// if unavailable: the restore is then eager).
func (r *restorer) startLazy(work string) string {
	start := time.Now()
	unit, err := startLazyPages(r.inv.id, r.finalDir(), work, r.dir)
	if err != nil {
		logf("container %s: lazy pages unavailable, eager restore: %v", r.name, err)
		return ""
	}
	logf("container %s: lazy-pages daemon ready (%d ms)", r.name, time.Since(start).Milliseconds())
	return unit
}

// runRestore runs runc restore; on failure it keeps CRIU's log for
// diagnosis and stops a lazy-pages daemon CRIU never connected to (it would
// wait in accept() for good and keep the images – the whole memory – from
// being cleaned up).
func (r *restorer) runRestore(rargs []string, work, lazyUnit string) error {
	start := time.Now()
	code := runRunc(r.inv.global, "restore", rargs, r.inv.id, r.inv.preserveFDs)
	r.res.RestoreMs = time.Since(start).Milliseconds()
	if code == 0 {
		return nil
	}
	// Before runc overwrites the work directory on the next attempt.
	b, err := os.ReadFile(filepath.Join(work, "restore.log"))
	if err != nil {
		// runc failed before CRIU ran (e.g. bad arguments): keep its log.
		b, _ = os.ReadFile(r.inv.logFile)
	}
	_ = os.WriteFile(filepath.Join(r.dir, "restore-failed.log"), b, 0o600)
	// runc cleans up a failed restore itself; just to be safe:
	_ = exec.Command(runcPath(), append(r.inv.global, "delete", "--force", r.inv.id)...).Run()
	if lazyUnit != "" {
		_ = exec.Command("systemctl", "stop", lazyUnit).Run()
	}
	reason := fmt.Sprintf("runc restore exit %d", code)
	if s := criulog.Summary(string(b)); s != "" {
		reason += ": criu: " + s
	}
	return fmt.Errorf("%s (log: %s/restore-failed.log)", reason, r.dir)
}

// finish records the restore: generic mode aborts the old connections, the
// markers tell `start` and the agent, and the shield goes down once every
// container of the pod is done.
func (r *restorer) finish(addrs []string) {
	if r.spec.Ann(names.AnnotationTCP) == names.TCPClose {
		if err := abortConnections(r.spec.NetNSPath(), addrs); err != nil {
			logf("container %s: could not abort the old connections: %v", r.name, err)
		} else {
			logf("container %s: connections on the old IP aborted (generic mode)", r.name)
		}
	}
	// Without these markers `start` would run an already running container
	// and the agent would never report the restore: worth a log line.
	if err := os.MkdirAll(names.RunDir+"/restored", 0o700); err != nil {
		logf("container %s: restored marker: %v", r.name, err)
	}
	if err := os.WriteFile(restoredMarker(r.inv.id), []byte(r.uid), 0o600); err != nil {
		logf("container %s: restored marker: %v", r.name, err)
	}
	r.res.FinishedAt = time.Now()
	if err := layout.WriteJSONAtomic(filepath.Join(r.dir, names.FileRestored), r.res); err != nil {
		logf("container %s: %s: %v", r.name, names.FileRestored, err)
	}
	logf("container %s: restored in %d ms (wait %d, delta %d, restore %d)",
		r.name, r.res.FinishedAt.Sub(r.res.StartedAt).Milliseconds(), r.res.WaitMs, r.res.ApplyMs, r.res.RestoreMs)
	lowerShieldIfDone(r.uid, r.spec)
}

// patchedCRIU returns a CRIU binary that carries Paguro's patches. Only such
// a CRIU may serve lazy pages after pre-copy: an unpatched lazy-pages daemon
// never completes page faults for pages that live in parent images, and the
// restored process hangs on its first such access. Candidates are the
// node-installer bundle and a CRIU built with the patches under
// /usr/local (build/criu-patches/); each writes the fingerprint of the
// applied patches next to the binary.
func patchedCRIU() (string, error) {
	for _, c := range []struct{ bin, stamp string }{
		{"/opt/paguro/bin/criu", "/opt/paguro/criu-patches.sha256"},
		{"/usr/local/sbin/criu", "/usr/local/share/paguro-criu-patches.sha256"},
	} {
		st, err := os.ReadFile(c.stamp)
		if err != nil || len(strings.TrimSpace(string(st))) == 0 {
			continue
		}
		if fi, err := os.Stat(c.bin); err == nil && fi.Mode()&0o111 != 0 {
			return c.bin, nil
		}
	}
	return "", fmt.Errorf("no CRIU with Paguro's patches found (needs /opt/paguro/criu-patches.sha256 or /usr/local/share/paguro-criu-patches.sha256)")
}

// startLazyPages starts CRIU's page daemon for a post-copy restore. It runs as
// a transient systemd unit because it has to outlive this wrapper: runc
// restore --detach returns as soon as the process runs, while the daemon keeps
// serving page faults and pushing the remaining pages from the local
// checkpoint until every page is in place, then exits on its own.
//
// The daemon and `runc restore --lazy-pages` meet through the socket
// lazy-pages.socket in the shared work directory.
func startLazyPages(id, images, work, dir string) (string, error) {
	unit := "paguro-lazy-" + id
	if len(unit) > 40 {
		unit = unit[:40]
	}
	criu, err := patchedCRIU()
	if err != nil {
		return "", err
	}
	out, err := exec.Command("systemd-run", "--unit="+unit, "--collect", "--quiet",
		"-p", "StandardOutput=file:"+filepath.Join(dir, "lazy-pages.out"),
		"-p", "StandardError=file:"+filepath.Join(dir, "lazy-pages.out"),
		criu, "lazy-pages", "--images-dir", images, "--work-dir", work,
		"--log-file", "lazy-pages.log", "-v4").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("systemd-run: %v: %s", err, strings.TrimSpace(string(out)))
	}
	sock := filepath.Join(work, "lazy-pages.socket")
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if layout.Exists(sock) {
			return unit, nil
		}
		time.Sleep(time.Millisecond) // inside the freeze
	}
	_ = exec.Command("systemctl", "stop", unit).Run()
	return "", fmt.Errorf("lazy-pages socket did not appear in %s", work)
}

// applyEmptyDirs applies emptyDir contents exactly once per pod – several
// containers can mount the same volume. A flock serializes this.
func applyEmptyDirs(uid string, spec *ocispec.Spec) error {
	lockPath := filepath.Join(layout.Root(uid), "emptydir.lock")
	lf, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lf.Close()
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lf.Fd()), syscall.LOCK_UN)

	for _, m := range spec.Mounts {
		_, vol, ok := strings.Cut(m.Source, "/volumes/kubernetes.io~empty-dir/")
		switch {
		case ok && !strings.Contains(vol, "/"):
		case sandboxShm(m):
			vol = layout.DevShmVolume // the pod's own /dev/shm
		default:
			continue
		}
		tarPath := layout.EmptyDirTar(uid, vol)
		done := tarPath + ".applied"
		if layout.Exists(done) {
			continue
		}
		base, delta := layout.EmptyDirBase(uid, vol), layout.EmptyDirDeltaTar(uid, vol)
		switch {
		case layout.Exists(delta):
			// The content came during pre-copy (unpacked next to the
			// checkpoint), the freeze brought only the changes.
			if !layout.Exists(base + ".complete") {
				return fmt.Errorf("%s: a delta without its base", vol)
			}
			start := time.Now()
			if err := moveTree(base, m.Source); err != nil {
				return fmt.Errorf("%s: base: %w", vol, err)
			}
			st, err := unpackFile(delta, m.Source, archive.UnpackOptions{Overlay: true})
			if err != nil {
				return fmt.Errorf("%s: delta: %w", vol, err)
			}
			logf("emptyDir %s: base moved, delta %d files, %d whiteouts, %d bytes (%d ms)", vol, st.Files, st.Whiteouts, st.Bytes,
				time.Since(start).Milliseconds())
		case layout.Exists(tarPath):
			st, err := unpackFile(tarPath, m.Source, archive.UnpackOptions{})
			if err != nil {
				return fmt.Errorf("%s: %w", vol, err)
			}
			logf("emptyDir %s: %d files, %d bytes to %s", vol, st.Files, st.Bytes, m.Source)
		default:
			continue
		}
		if err := os.WriteFile(done, nil, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// sandboxShm: m is the pod's own /dev/shm – containerd's tmpfs of the
// sandbox, bind-mounted into the container. Not a volume of the pod, and
// never the host's /dev/shm (hostIPC pods are not migrated). A /dev/shm of
// the container's own (a tmpfs mount) CRIU carries itself.
func sandboxShm(m ocispec.Mount) bool {
	if path.Clean(m.Destination) != "/dev/shm" || !filepath.IsAbs(m.Source) || path.Clean(m.Source) == "/dev/shm" ||
		strings.Contains(m.Source, "/volumes/kubernetes.io~") {
		return false
	}
	return m.Type == "bind" || slices.Contains(m.Options, "bind") || slices.Contains(m.Options, "rbind")
}

func unpackFile(path, dst string, opt archive.UnpackOptions) (archive.Stats, error) {
	f, err := os.Open(path)
	if err != nil {
		return archive.Stats{}, err
	}
	defer f.Close()
	return archive.Unpack(f, dst, opt)
}

// moveTree moves the entries of src into dst: renames on the same
// filesystem (no copy inside the freeze), a copy otherwise (an emptyDir
// on tmpfs).
func moveTree(src, dst string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, e := range entries {
		from, to := filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())
		err := os.Rename(from, to)
		if errors.Is(err, syscall.EXDEV) {
			err = copyTree(from, filepath.Dir(to))
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// copyTree copies src into the directory dstParent (tar through a pipe:
// owners, modes, links and times as in a transfer).
func copyTree(src, dstParent string) error {
	pr, pw := io.Pipe()
	go func() {
		_, err := archive.Pack(pw, filepath.Dir(src), archive.PackOptions{Exclude: siblingsOf(src)})
		pw.CloseWithError(err)
	}()
	_, err := archive.Unpack(pr, dstParent, archive.UnpackOptions{})
	pr.CloseWithError(err)
	return err
}

// siblingsOf lists, as Pack excludes, the other entries next to p.
func siblingsOf(p string) []string {
	entries, _ := os.ReadDir(filepath.Dir(p))
	var out []string
	for _, e := range entries {
		if e.Name() != filepath.Base(p) {
			out = append(out, "/"+e.Name())
		}
	}
	return out
}

// aborted reports that the migration ended before its commit (the target
// agent's marker, names.FileAborted).
func aborted(uid string) bool {
	return layout.Exists(filepath.Join(layout.Root(uid), names.FileAborted))
}

// lowerShieldIfDone lowers the shield as soon as all containers of the pod
// are restored (or cold-started). Before that, a container restored early
// would answer segments for sockets of a sibling that is not yet restored
// with RST.
func lowerShieldIfDone(uid string, spec *ocispec.Spec) {
	meta, err := layout.ReadMeta(uid)
	if err != nil {
		return
	}
	for _, c := range meta.Containers {
		d := layout.ContainerDir(uid, c.Name)
		if !layout.Exists(filepath.Join(d, names.FileRestored)) && !layout.Exists(filepath.Join(d, names.FileColdStart)) {
			return
		}
	}
	if err := shield.Lower(shield.Exec, spec.NetNSPath()); err != nil {
		logf("lower shield: %v", err)
		return
	}
	logf("all containers of %s/%s restored – shield lowered", meta.Namespace, meta.Migration)
}

// abortConnections destroys the connected TCP sockets on the old addresses
// (generic mode): the network no longer routes them to this pod. The
// application gets ECONNABORTED at once and can reconnect, instead of
// waiting for a timeout. Connections over loopback inside the pod (app <->
// sidecar) stay. IPv4 addresses are matched in both forms: dual-stack
// servers hold them as v4-mapped IPv6 sockets.
func abortConnections(netns string, oldAddrs []string) error {
	if netns == "" || len(oldAddrs) == 0 {
		return nil
	}
	var terms []string
	for _, a := range oldAddrs {
		terms = append(terms, "src "+a)
		if !strings.Contains(a, ":") {
			terms = append(terms, "src [::ffff:"+a+"]")
		}
	}
	filter := "( " + strings.Join(terms, " or ") + " )"
	_, err := shield.Exec("", "nsenter", "--net="+netns, "ss", "-K", "-t", "-n", "state", "connected", filter)
	return err
}

// removeCRIUNetworkLock deletes nftables tables that a failed CRIU restore
// left in the pod's network namespace. CRIU locks the network with a table
// named "CRIU-<uuid>" that drops all traffic; when the restore fails it is
// not always removed (observed with "Can't bind inet socket back"), and the
// cold-started pod would never pass a readiness probe.
func removeCRIUNetworkLock(netns string) {
	if netns == "" {
		return
	}
	out, err := shield.Exec("", "nsenter", "--net="+netns, "nft", "list", "tables")
	if err != nil {
		return
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line) // "table inet CRIU-..."
		if len(f) == 3 && f[0] == "table" && strings.HasPrefix(f[2], "CRIU-") {
			if _, err := shield.Exec("", "nsenter", "--net="+netns, "nft", "delete", "table", f[1], f[2]); err == nil {
				logf("removed CRIU network lock %s %s left by the failed restore", f[1], f[2])
			}
		}
	}
}

func restoredMarker(id string) string { return filepath.Join(names.RunDir, "restored", id) }

func isRestored(id string) bool { return id != "" && layout.Exists(restoredMarker(id)) }
