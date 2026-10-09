// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

// Source side, part 5: what goes to the target besides the memory images –
// rootfs and emptyDir deltas, the metadata – and the status counters.

package agent

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	v1 "paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/archive"
	"paguro.dev/paguro/internal/layout"
)

func (j *sourceJob) localFile(rel string) string {
	return j.a.Host.Path(filepath.Join(j.dumpRoot(), rel))
}

func (j *sourceJob) captureFilesystems(ctx context.Context) error {
	pack := func(dst, src string, overlay bool) (archive.Stats, error) {
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return archive.Stats{}, err
		}
		f, err := os.Create(dst)
		if err != nil {
			return archive.Stats{}, err
		}
		defer f.Close()
		return archive.Pack(f, src, archive.PackOptions{Overlay: overlay, Exclude: []string{"/dev", "/proc", "/sys"}})
	}
	for _, c := range j.cs {
		st, err := pack(j.localFile(filepath.Join("containers", c.name, v1.FileRootfsDiff)), j.a.Host.Path(c.upper), true)
		if err != nil {
			return fmt.Errorf("%s: %w", c.name, err)
		}
		c.stat.RootfsDiffBytes = st.Bytes
	}
	var mapped map[string]bool
	for _, vol := range j.pod.Spec.Volumes {
		if vol.EmptyDir == nil {
			continue
		}
		src := j.emptyDirPath(vol.Name)
		base, ok := j.emptyDirBases[vol.Name]
		if !ok {
			if _, err := pack(j.localFile(filepath.Join("emptydir", vol.Name+".tar")), src, false); err != nil {
				return fmt.Errorf("emptyDir %s: %w", vol.Name, err)
			}
			continue
		}
		// Only what changed since the base (sent during pre-copy), and the
		// files mapped writable by the pod's processes: their mtime may lag.
		if mapped == nil {
			mapped = j.writableMappings(ctx)
		}
		dst := j.localFile(filepath.Join("emptydir", vol.Name+".delta.tar"))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return err
		}
		f, err := os.Create(dst)
		if err != nil {
			return err
		}
		prefix := vol.Name + "/"
		st, err := archive.Pack(f, src, archive.PackOptions{Since: base,
			Always: func(name string) bool { return mapped[prefix+name] }})
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return fmt.Errorf("emptyDir %s: %w", vol.Name, err)
		}
		j.log.Info("emptyDir delta", "volume", vol.Name, "files", st.Files, "whiteouts", st.Whiteouts, "bytes", st.Bytes)
	}
	return j.captureDevShm()
}

// captureDevShm saves the pod's own /dev/shm while the pod is paused. It is
// the sandbox's tmpfs, bind-mounted into every container – not a volume,
// and for CRIU a mount from outside, whose files it expects to find again
// at the restore: PostgreSQL's dynamic shared memory, Ruby's metrics files
// (GitLab on EKS: "Can't open file dev/shm/gitlab/sidekiq/…", then a cold
// start). The restore wrapper unpacks it into the replacement's /dev/shm.
func (j *sourceJob) captureDevShm() error {
	src := devShmOf(j.pod, j.cs)
	if src == "" {
		return nil
	}
	entries, err := os.ReadDir(src)
	if err != nil || len(entries) == 0 {
		return nil // none, or empty: nothing to carry
	}
	dst := j.localFile(filepath.Join("emptydir", layout.DevShmVolume+".tar"))
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	st, err := archive.Pack(f, src, archive.PackOptions{})
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("/dev/shm: %w", err)
	}
	j.devShm = true
	j.log.Info("/dev/shm carried", "files", st.Files, "bytes", st.Bytes)
	return nil
}

// devShmOf returns the pod's own /dev/shm, as seen through a container that
// has no volume there ("" if every container mounts one at /dev/shm or
// /dev: an emptyDir there travels as such).
func devShmOf(pod *corev1.Pod, cs []*srcContainer) string {
	if pod == nil || pod.Spec.HostIPC {
		return "" // the host's (refused by the preflight anyway)
	}
	mounted := map[string]bool{}
	for _, c := range pod.Spec.Containers {
		for _, vm := range c.VolumeMounts {
			if p := path.Clean(vm.MountPath); p == "/dev/shm" || p == "/dev" {
				mounted[c.Name] = true
			}
		}
	}
	for _, c := range cs {
		if !mounted[c.name] && c.pid > 0 {
			return fmt.Sprintf("/proc/%d/root/dev/shm", c.pid)
		}
	}
	return ""
}

// emptyDirPath is an emptyDir of the source pod on the host.
func (j *sourceJob) emptyDirPath(vol string) string {
	return j.a.Host.Path(filepath.Join("/var/lib/kubelet/pods", string(j.pod.UID), "volumes/kubernetes.io~empty-dir", vol))
}

// sendEmptyDirBases sends every emptyDir's content during pre-copy and
// keeps what was sent (archive.Manifest): the freeze then only carries the
// changes. Measured before: a Minecraft Bedrock server keeps its 233 MB
// binary in its data directory, and packing and sending all of it took
// 3.4 s of a 5.1 s freeze. A failed base costs only that speed-up.
func (j *sourceJob) sendEmptyDirBases(ctx context.Context) {
	for _, vol := range j.pod.Spec.Volumes {
		if vol.EmptyDir == nil {
			continue
		}
		start := time.Now()
		base := archive.Manifest{}
		st, err := j.client.Send(ctx, "PUT", fmt.Sprintf("/v1/m/%s/emptydir/%s/base", j.m.UID, vol.Name), func(w io.Writer) error {
			_, err := archive.Pack(w, j.emptyDirPath(vol.Name), archive.PackOptions{Record: base})
			return err
		})
		if err != nil {
			j.log.Warn("emptyDir base not sent – the freeze carries all of it", "volume", vol.Name, "err", err)
			continue
		}
		if j.emptyDirBases == nil {
			j.emptyDirBases = map[string]archive.Manifest{}
		}
		j.emptyDirBases[vol.Name] = base
		j.log.Info("emptyDir base sent", "volume", vol.Name, "entries", len(base), "wireBytes", st.WireBytes,
			"ms", ms(time.Since(start)))
	}
}

// writableMappings lists the files the pod's processes have mapped shared
// and writable inside an emptyDir, as "<volume>/<name>": a write through
// such a mapping does not always move the file's mtime.
func (j *sourceJob) writableMappings(ctx context.Context) map[string]bool {
	mounts := map[string]string{} // mount path in a container → "<volume>/<subPath>"
	empty := map[string]bool{}
	for _, v := range j.pod.Spec.Volumes {
		if v.EmptyDir != nil {
			empty[v.Name] = true
		}
	}
	for _, c := range append(j.pod.Spec.Containers, j.pod.Spec.InitContainers...) {
		for _, vm := range c.VolumeMounts {
			if empty[vm.Name] {
				mounts[filepath.Clean(vm.MountPath)] = path.Join(vm.Name, vm.SubPath)
			}
		}
	}
	out := map[string]bool{}
	for _, pid := range j.podPIDs(ctx) {
		b, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 6 || !strings.Contains(fields[1], "w") || !strings.Contains(fields[1], "s") {
				continue
			}
			file := strings.Join(fields[5:], " ")
			for mp, rel := range mounts {
				if name, ok := strings.CutPrefix(file, mp+"/"); ok {
					out[path.Join(rel, name)] = true
				}
			}
		}
	}
	return out
}

// finalMeta is the metadata the target restores from.
func (j *sourceJob) finalMeta(frozenAt time.Time, rounds int) layout.Meta {
	meta := layout.Meta{
		Migration: j.m.Name, Namespace: j.m.Namespace, UID: string(j.m.UID),
		SourceNode: j.a.NodeName, SourceIP: j.m.Status.SourcePodIP, FrozenAt: frozenAt,
		BoundIPs: j.boundIPs,
	}
	for _, c := range j.cs {
		meta.Containers = append(meta.Containers, layout.ContainerMeta{
			Name: c.name, Image: c.image, Rounds: rounds,
			Opts:      layout.DumpOptions{TCPEstablished: true, FileLocks: true},
			LazyPages: c.rss >= lazyPagesMinRSS,
		})
	}
	if j.pod != nil {
		for _, v := range j.pod.Spec.Volumes {
			if v.EmptyDir != nil {
				meta.EmptyDirs = append(meta.EmptyDirs, v.Name)
			}
		}
	}
	if j.devShm {
		meta.EmptyDirs = append(meta.EmptyDirs, layout.DevShmVolume)
	}
	return meta
}

func (j *sourceJob) sendMeta(ctx context.Context, frozenAt time.Time, rounds int) error {
	_, err := j.client.Send(ctx, "PUT", fmt.Sprintf("/v1/m/%s/meta", j.m.UID), func(w io.Writer) error {
		return jsonEncode(w, j.finalMeta(frozenAt, rounds))
	})
	return err
}

func (j *sourceJob) sendFinal(ctx context.Context, rounds int, frozenAt time.Time, step func(string, time.Duration), gate func() error) error {
	byName := map[string]*srcContainer{}
	for _, c := range j.cs {
		byName[c.name] = c
	}
	return j.a.sendFinal(ctx, finalSend{
		UID: string(j.m.UID), Client: j.client, Meta: j.finalMeta(frozenAt, rounds), DumpRoot: j.dumpRoot(),
		Account: func(n int64) {
			j.mu.Lock()
			j.wire += n
			j.mu.Unlock()
		},
		Done: func(name string, st SendStats, d time.Duration) {
			j.mu.Lock()
			defer j.mu.Unlock()
			if c := byName[name]; c != nil && len(c.stat.Rounds) > 0 {
				last := &c.stat.Rounds[len(c.stat.Rounds)-1]
				last.WireBytes, last.SendMs = st.WireBytes, ms(d)
			}
		},
		Step: step,
		Gate: gate,
	})
}

func (j *sourceJob) containerStats() []v1.ContainerStatus {
	out := make([]v1.ContainerStatus, 0, len(j.cs))
	for _, c := range j.cs {
		out = append(out, c.stat)
	}
	return out
}

// countTCP counts the dumped TCP connections (entries in tcp-stream-*.img).
func countTCP(dir string) int32 {
	entries, _ := os.ReadDir(dir)
	var n int32
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "tcp-stream-") {
			n++
		}
	}
	return n
}
