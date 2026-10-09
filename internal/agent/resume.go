// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

// The transfer after the commit, and its resumption.
//
// After the commit the source pod is deleted; the frozen state exists only
// in the dump directory on the source node, and the target waits for it.
// If the source agent is restarted in between, the transfer was lost with
// the job – the target would wait for its timeout and then cold-start: the
// workload's memory gone. So the source keeps everything the transfer needs
// next to the dump (resume.json: the metadata exactly as sent) and records
// each container whose data is complete at the target (sent-ready). A
// restarted agent sends the rest. A container already marked ready is never
// sent again: the target may be restoring from those images.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	v1 "paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/archive"
	"paguro.dev/paguro/internal/layout"
)

const (
	fileResume    = "resume.json"
	fileSentReady = "sent-ready"
)

// finalSend describes one transfer after the commit.
type finalSend struct {
	UID      string
	Client   *Client
	Meta     layout.Meta
	DumpRoot string // dump directory (host path)
	// Account receives wire bytes; Done is called per container whose
	// data is complete (stats of its final images). Both may be nil.
	Account func(int64)
	Done    func(container string, st SendStats, d time.Duration)
	// Step (may be nil) records how long a step took.
	Step func(name string, d time.Duration)
	// Gate (may be nil) is called before every READY: the commit. The data
	// goes out before it; an error means no READY may follow.
	Gate func() error
}

// sendFinal sends the metadata, emptyDirs, final images and rootfs deltas
// and marks every container ready. Containers recorded in sent-ready are
// skipped, and so is one the target reports complete (errComplete): READY
// may have arrived just before an agent restart, without the record.
func (a *Agent) sendFinal(ctx context.Context, f finalSend) error {
	snd := &finalSender{a: a, f: f}
	if err := snd.sendMeta(ctx); err != nil {
		return err
	}
	for _, vol := range f.Meta.EmptyDirs {
		if err := snd.sendEmptyDir(ctx, vol); err != nil {
			return fmt.Errorf("emptyDir %s: %w", vol, err)
		}
	}
	snd.sentFile = snd.local(fileSentReady)
	done := readSentReady(snd.sentFile)
	var wg sync.WaitGroup
	errs := make([]error, len(f.Meta.Containers))
	for i, c := range f.Meta.Containers {
		if slices.Contains(done, c.Name) {
			continue
		}
		wg.Go(func() { errs[i] = snd.sendContainer(ctx, c.Name) })
	}
	wg.Wait()
	return errors.Join(errs...)
}

// finalSender is one run of sendFinal.
type finalSender struct {
	a        *Agent
	f        finalSend
	sentFile string
	mu       sync.Mutex // sent-ready record and step reports
}

func (snd *finalSender) local(rel string) string {
	return snd.a.Host.Path(filepath.Join(snd.f.DumpRoot, rel))
}

func (snd *finalSender) account(st SendStats) {
	if snd.f.Account != nil {
		snd.f.Account(st.WireBytes)
	}
}

func (snd *finalSender) putFile(ctx context.Context, path, file string) error {
	st, err := snd.f.Client.Send(ctx, "PUT", path, func(w io.Writer) error {
		fh, err := os.Open(file)
		if err != nil {
			return err
		}
		defer fh.Close()
		_, err = io.Copy(w, fh)
		return err
	})
	snd.account(st)
	return err
}

func (snd *finalSender) sendMeta(ctx context.Context) error {
	start := time.Now()
	if _, err := snd.f.Client.Send(ctx, "PUT", fmt.Sprintf("/v1/m/%s/meta", snd.f.UID), func(w io.Writer) error {
		return jsonEncode(w, snd.f.Meta)
	}); err != nil {
		return err
	}
	if snd.f.Step != nil {
		snd.f.Step("metaMs", time.Since(start))
	}
	return nil
}

// sendEmptyDir sends the delta to a base sent during pre-copy, or the
// whole content.
func (snd *finalSender) sendEmptyDir(ctx context.Context, vol string) error {
	path, file := fmt.Sprintf("/v1/m/%s/emptydir/%s", snd.f.UID, vol), snd.local(filepath.Join("emptydir", vol+".tar"))
	if delta := snd.local(filepath.Join("emptydir", vol+".delta.tar")); layout.Exists(delta) {
		path, file = path+"/delta", delta
	}
	return snd.putFile(ctx, path, file)
}

// sendContainer sends a container's final images and rootfs delta, waits
// for the gate and marks it ready.
func (snd *finalSender) sendContainer(ctx context.Context, name string) error {
	f := snd.f
	start := time.Now()
	dir := snd.local(filepath.Join("containers", name, v1.DirImages, "final"))
	st, err := f.Client.Send(ctx, "PUT", fmt.Sprintf("/v1/m/%s/c/%s/images/final", f.UID, name), func(w io.Writer) error {
		_, err := archive.Pack(w, dir, archive.PackOptions{})
		return err
	})
	snd.account(st)
	if errors.Is(err, errComplete) {
		snd.sent(name)
		return nil
	}
	if err != nil {
		return fmt.Errorf("%s final: %w", name, err)
	}
	d := time.Since(start)
	rstart := time.Now()
	if err := snd.putFile(ctx, fmt.Sprintf("/v1/m/%s/c/%s/rootfs", f.UID, name), snd.local(filepath.Join("containers", name, v1.FileRootfsDiff))); err != nil {
		return fmt.Errorf("%s rootfs: %w", name, err)
	}
	rend := time.Now()
	if f.Gate != nil {
		if err := f.Gate(); err != nil {
			return err
		}
	}
	mstart := time.Now()
	if err := f.Client.Marker(ctx, f.UID, name, "ready", ""); err != nil {
		return err
	}
	if f.Step != nil {
		snd.mu.Lock()
		f.Step(name+".imagesMs", d)
		f.Step(name+".rootfsMs", rend.Sub(rstart))
		f.Step(name+".gateMs", mstart.Sub(rend))
		f.Step(name+".readyMs", time.Since(mstart))
		snd.mu.Unlock()
	}
	snd.sent(name)
	if f.Done != nil {
		f.Done(name, st, d)
	}
	return nil
}

// sent records a container as sent and ready (sent-ready).
func (snd *finalSender) sent(name string) {
	snd.mu.Lock()
	appendSentReady(snd.sentFile, name)
	snd.mu.Unlock()
}

func readSentReady(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if n := strings.TrimSpace(sc.Text()); n != "" {
			out = append(out, n)
		}
	}
	return out
}

func appendSentReady(path, name string) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = fmt.Fprintln(f, name)
	_ = f.Sync()
}

// resumable: this node is the source of a committed migration whose final
// transfer is not done, and no job of this process handles it – the agent
// was restarted after the commit.
func (a *Agent) resumable(m *v1.Migration) bool {
	switch m.Status.Phase {
	case v1.PhaseFrozen, v1.PhaseCuttingOver, v1.PhaseRestoring:
	default:
		return false
	}
	return m.Status.SourceNode == a.NodeName && m.Status.Source.FrozenAt != nil &&
		m.Status.Source.TransferDoneAt == nil && m.Status.Source.Error == "" && m.Status.Target.Endpoint != ""
}

// resumeTransfer sends the rest of a committed migration's data after an
// agent restart. Without a resume record the target is told at once that
// nothing more will come, so that it cold-starts now instead of after its
// timeout.
func (a *Agent) resumeTransfer(ctx context.Context, m *v1.Migration, log *slog.Logger) {
	uid := string(m.UID)
	dumpRoot := filepath.Join(v1.StateDir, "dump", uid)
	cl, err := a.newClient(m.Status.Target.Endpoint, m.Status.TargetNode)
	if err == nil {
		defer cl.Close()
	}
	var meta layout.Meta
	var b []byte
	if err == nil {
		b, err = os.ReadFile(a.Host.Path(filepath.Join(dumpRoot, fileResume)))
	}
	if err == nil {
		err = json.Unmarshal(b, &meta)
	}
	if err == nil {
		err = a.sendFinal(ctx, finalSend{UID: uid, Client: cl, Meta: meta, DumpRoot: dumpRoot})
	}
	if err != nil {
		reason := "the source agent was restarted after the commit and could not send the final data: " + err.Error()
		log.Error("resuming the transfer failed", "err", err)
		for _, c := range m.Status.Containers {
			if cl == nil {
				break
			}
			_ = cl.Marker(ctx, uid, c.Name, "failed", reason)
		}
		_ = a.patchStatus(ctx, m, map[string]any{"source": map[string]any{"error": reason}})
		return
	}
	log.Info("transfer resumed after an agent restart", "containers", len(meta.Containers))
	_ = a.patchStatus(ctx, m, map[string]any{"source": map[string]any{
		"transferDoneAt": now(), "message": "all data at the target (resumed after an agent restart)"}})
}
