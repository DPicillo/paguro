// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/klauspost/compress/zstd"

	"paguro.dev/paguro/internal/archive"
	"paguro.dev/paguro/internal/criuimg"
	"paguro.dev/paguro/internal/layout"
	"paguro.dev/paguro/pkg/names"
)

// Transfer protocol between the source and target agents. All bodies are
// zstd-compressed; images and emptyDirs are tar streams.
//
//	PUT  /v1/m/{uid}/meta                      meta.json
//	PUT  /v1/m/{uid}/c/{name}/images/{round}   tar → unpacked to images/{round}
//	PUT  /v1/m/{uid}/c/{name}/rootfs           tar → stored as a file (the wrapper applies it)
//	PUT  /v1/m/{uid}/emptydir/{vol}            tar → stored as a file (the wrapper applies it)
//	PUT  /v1/m/{uid}/emptydir/{vol}/base       tar during pre-copy → unpacked into a staging directory
//	PUT  /v1/m/{uid}/emptydir/{vol}/delta      tar of the changes since the base → stored as a file
//	POST /v1/m/{uid}/c/{name}/compacted        returns once every received round is in the base
//	POST /v1/m/{uid}/c/{name}/ready            marker READY
//	POST /v1/m/{uid}/c/{name}/failed           marker FAILED (body = reason)
//	GET  /healthz
//
// Once a container is READY the restore may be reading its data: images,
// rootfs and a FAILED marker for it are refused with 409 Conflict
// (errComplete at the client), READY again is a no-op.
//
// Authentication: a shared token from a Secret (Bearer) and, with transfer
// TLS, each node's certificate: a target takes a migration's data only from
// its source node (Agent.AuthorizeTransfer). The agent listens only on the
// node's InternalIP.

var safeName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,252}$`)

// errComplete: the target already has the container's complete data (READY)
// and may be restoring from it.
var errComplete = errors.New("the target already has the container's complete data")

// complete: the container's data is complete (READY); nothing of it may
// change any more. Answers 409 if so.
func complete(w http.ResponseWriter, uid, name string) bool {
	if !layout.Exists(filepath.Join(layout.ContainerDir(uid, name), names.FileReady)) {
		return false
	}
	http.Error(w, errComplete.Error(), http.StatusConflict)
	return true
}

// Server accepts checkpoint data.
type Server struct {
	Token string
	Log   *slog.Logger
	// Authorize, if set, decides whether the peer may send for a migration
	// (Agent.AuthorizeTransfer: only its source node, only to its target).
	Authorize func(r *http.Request, uid string) error

	rounds roundQueues
}

// readyTimeout bounds how long READY waits for the container's pre-copy
// rounds to be folded into its base image (and the source for its answer).
const readyTimeout = 10 * time.Minute

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") })
	mux.HandleFunc("PUT /v1/m/{uid}/meta", s.auth(s.putMeta))
	mux.HandleFunc("PUT /v1/m/{uid}/c/{name}/images/{round}", s.auth(s.putImages))
	mux.HandleFunc("PUT /v1/m/{uid}/c/{name}/rootfs", s.auth(s.putRootfs))
	mux.HandleFunc("PUT /v1/m/{uid}/emptydir/{vol}", s.auth(s.putEmptyDir))
	mux.HandleFunc("PUT /v1/m/{uid}/emptydir/{vol}/base", s.auth(s.putEmptyDirBase))
	mux.HandleFunc("PUT /v1/m/{uid}/emptydir/{vol}/delta", s.auth(s.putEmptyDirDelta))
	mux.HandleFunc("POST /v1/m/{uid}/c/{name}/compacted", s.auth(s.postCompacted))
	mux.HandleFunc("POST /v1/m/{uid}/c/{name}/{marker}", s.auth(s.postMarker))
	mux.HandleFunc("POST /v1/m/{uid}/handover", s.auth(s.postHandOver))
	return mux
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if s.Token == "" || subtle.ConstantTimeCompare([]byte(got), []byte(s.Token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		for _, k := range []string{"uid", "name", "round", "vol", "marker"} {
			if v := r.PathValue(k); v != "" && !safeName.MatchString(v) {
				http.Error(w, "bad "+k, http.StatusBadRequest)
				return
			}
		}
		if s.Authorize != nil {
			if err := s.Authorize(r, r.PathValue("uid")); err != nil {
				transferRefused.Inc()
				if s.Log != nil {
					s.Log.Warn("transfer request refused", "remote", r.RemoteAddr, "path", r.URL.Path, "err", err)
				}
				http.Error(w, err.Error(), http.StatusForbidden)
				return
			}
		}
		next(w, r)
	}
}

func (s *Server) body(r *http.Request) (io.ReadCloser, error) {
	d, err := zstd.NewReader(r.Body, zstd.WithDecoderConcurrency(2))
	if err != nil {
		return nil, err
	}
	return d.IOReadCloser(), nil
}

func (s *Server) putMeta(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("uid")
	rc, err := s.body(r)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	defer rc.Close()
	m := &layout.Meta{}
	if err := json.NewDecoder(rc).Decode(m); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if err := m.Validate(); err != nil {
		http.Error(w, "meta.json: "+err.Error(), 400)
		return
	}
	if err := layout.WriteJSONAtomic(filepath.Join(layout.Root(uid), names.FileMeta), m); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) putImages(w http.ResponseWriter, r *http.Request) {
	uid, name, round := r.PathValue("uid"), r.PathValue("name"), r.PathValue("round")
	if complete(w, uid, name) {
		return
	}
	dst := filepath.Join(layout.ImagesDir(uid, name), round)
	start := time.Now()
	rc, err := s.body(r)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	defer rc.Close()
	// When a round is retried (network error), start over cleanly – but not
	// while its first copy is still being applied to the base.
	if err := s.rounds.awaitRound(r.Context(), uid, name, round); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	_ = os.RemoveAll(dst)
	if err := os.MkdirAll(dst, 0o700); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	st, err := archive.Unpack(rc, dst, archive.UnpackOptions{})
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.Log.Info("images received", "uid", uid, "container", name, "round", round,
		"files", st.Files, "bytes", st.Bytes, "ms", time.Since(start).Milliseconds())
	if round != "final" {
		// Fold the pre-copy round into the flat base image (see
		// internal/criuimg/compact.go) in the background: the source sends
		// the next round meanwhile (roundqueue.go). A round that cannot be
		// applied breaks the chain – later rounds and READY are refused.
		base := filepath.Join(layout.ImagesDir(uid, name), "base")
		err := s.rounds.add(uid, name, round, func() error {
			cstart := time.Now()
			cst, err := criuimg.ApplyRound(base, dst)
			if err != nil {
				s.Log.Warn("compaction failed", "uid", uid, "container", name, "round", round, "err", err)
				return err
			}
			s.Log.Info("round compacted", "uid", uid, "container", name, "round", round,
				"mode", cst.Mode, "pagesInPlace", cst.PagesInPlace, "pagesNew", cst.PagesNew, "ms", time.Since(cstart).Milliseconds())
			return nil
		})
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) putFile(w http.ResponseWriter, r *http.Request, dst string) {
	rc, err := s.body(r)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	defer rc.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	f, err := os.Create(dst + ".part")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	_, err = io.Copy(f, rc)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(dst+".part", dst)
	}
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) putRootfs(w http.ResponseWriter, r *http.Request) {
	if complete(w, r.PathValue("uid"), r.PathValue("name")) {
		return
	}
	s.putFile(w, r, filepath.Join(layout.ContainerDir(r.PathValue("uid"), r.PathValue("name")), names.FileRootfsDiff))
}

func (s *Server) putEmptyDir(w http.ResponseWriter, r *http.Request) {
	s.putFile(w, r, layout.EmptyDirTar(r.PathValue("uid"), r.PathValue("vol")))
}

func (s *Server) putEmptyDirDelta(w http.ResponseWriter, r *http.Request) {
	s.putFile(w, r, layout.EmptyDirDeltaTar(r.PathValue("uid"), r.PathValue("vol")))
}

// putEmptyDirBase unpacks an emptyDir's pre-copied content into its staging
// directory – during pre-copy, so that the restore only moves it into the
// new pod's emptyDir and applies the small delta of the freeze.
func (s *Server) putEmptyDirBase(w http.ResponseWriter, r *http.Request) {
	uid, vol := r.PathValue("uid"), r.PathValue("vol")
	rc, err := s.body(r)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	defer rc.Close()
	dir := layout.EmptyDirBase(uid, vol)
	_ = os.Remove(dir + ".complete")
	_ = os.RemoveAll(dir) // a retry starts over
	if err := os.MkdirAll(dir, 0o700); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	start := time.Now()
	st, err := archive.Unpack(rc, dir, archive.UnpackOptions{})
	if err == nil {
		err = os.WriteFile(dir+".complete", nil, 0o600)
	}
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.Log.Info("emptyDir base received", "uid", uid, "volume", vol, "files", st.Files, "bytes", st.Bytes,
		"ms", time.Since(start).Milliseconds())
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) postMarker(w http.ResponseWriter, r *http.Request) {
	var file string
	switch r.PathValue("marker") {
	case "ready":
		file = names.FileReady
	case "failed":
		file = names.FileFailed
	default:
		http.NotFound(w, r)
		return
	}
	reason, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
	uid, name := r.PathValue("uid"), r.PathValue("name")
	dir := layout.ContainerDir(uid, name)
	if layout.Exists(filepath.Join(dir, names.FileReady)) {
		if file == names.FileReady {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Error(w, errComplete.Error(), http.StatusConflict)
		return
	}
	if file == names.FileReady {
		// The restore reads the compacted images: all rounds applied first.
		ctx, cancel := context.WithTimeout(r.Context(), readyTimeout)
		err := s.rounds.drain(ctx, uid, name)
		cancel()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
	}
	defer s.rounds.forget(uid, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if err := os.WriteFile(filepath.Join(dir, file), reason, 0o600); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// postCompacted answers once the container's received pre-copy rounds are
// folded into its base image (500 if one could not be). The source asks
// right before the freeze: the last round's compaction must not run inside
// it (READY would wait for it – measured: freeze +60 ms for small pods).
func (s *Server) postCompacted(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), readyTimeout)
	defer cancel()
	if err := s.rounds.drain(ctx, r.PathValue("uid"), r.PathValue("name")); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// postHandOver records that the source is paused (early hand-over): the
// commit gate releases the replacement on it (dragate.go).
func (s *Server) postHandOver(w http.ResponseWriter, r *http.Request) {
	root := layout.Root(r.PathValue("uid"))
	if err := os.MkdirAll(root, 0o700); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if err := layout.WriteJSONAtomic(filepath.Join(root, names.FileHandOver), time.Now()); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

// Client sends to a target agent.
type Client struct {
	// Endpoint is "host:port" (plain HTTP) or "https://host:port".
	Endpoint string
	Token    string
	HTTP     *http.Client
}

// NewClient refuses a mismatch between the endpoint's scheme and this
// agent's transfer TLS (nil: none). With TLS the server must hold the
// certificate of targetNode.
func NewClient(endpoint, token string, tlsFiles *TransferTLS, targetNode string) (*Client, error) {
	tr := &http.Transport{
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		DisableCompression:  true,
		MaxIdleConnsPerHost: 8,
		// Every migration gets its own client; idle connections must not
		// outlive it (Close).
		IdleConnTimeout: 90 * time.Second,
		// Go's buffers between the stream and the connection (not the
		// kernel's socket buffers): fewer, larger writes.
		WriteBufferSize: 1 << 20,
		ReadBufferSize:  64 << 10,
	}
	secure := strings.HasPrefix(endpoint, "https://")
	switch {
	case secure && tlsFiles == nil:
		return nil, fmt.Errorf("target agent %s uses transfer TLS, this agent has no transfer certificate", endpoint)
	case !secure && tlsFiles != nil:
		return nil, fmt.Errorf("target agent %s serves plain HTTP (TLS disabled there or an older version): "+
			"refusing to send memory images unencrypted", endpoint)
	case secure:
		cfg, err := tlsFiles.ClientConfig(targetNode)
		if err != nil {
			return nil, err
		}
		tr.TLSClientConfig = cfg
		tr.TLSHandshakeTimeout = 5 * time.Second
	}
	return &Client{Endpoint: endpoint, Token: token, HTTP: &http.Client{Transport: tr}}, nil
}

// Close releases the client's idle connections.
func (c *Client) Close() { c.HTTP.CloseIdleConnections() }

// controlTimeout bounds one small control request (hand-over, marker): a
// stalled attempt must not use up its caller's whole retry budget.
const controlTimeout = 5 * time.Second

func (c *Client) url(path string) string {
	if strings.Contains(c.Endpoint, "://") {
		return c.Endpoint + path
	}
	return "http://" + c.Endpoint + path
}

// encoderConcurrency: zstd encoder goroutines per transfer.
var encoderConcurrency = 2

// SendStats holds the measurements of one transfer.
type SendStats struct {
	RawBytes  int64 // before compression
	WireBytes int64 // on the wire
	Duration  time.Duration
}

// Send compresses what produce writes into the writer and sends it via
// PUT/POST. produce runs in parallel with the transfer (pipe) – packing,
// compressing and sending overlap.
func (c *Client) Send(ctx context.Context, method, path string, produce func(io.Writer) error) (SendStats, error) {
	start := time.Now()
	pr, pw := io.Pipe()
	var raw, wire atomic.Int64
	go func() {
		cw := &countingWriter{w: pw, n: &wire}
		enc, err := zstd.NewWriter(cw, zstd.WithEncoderLevel(zstd.SpeedFastest), zstd.WithEncoderConcurrency(encoderConcurrency))
		if err != nil {
			pw.CloseWithError(err)
			return
		}
		err = produce(&countingWriter{w: enc, n: &raw})
		if cerr := enc.Close(); err == nil {
			err = cerr
		}
		pw.CloseWithError(err)
	}()
	req, err := http.NewRequestWithContext(ctx, method, c.url(path), pr)
	if err != nil {
		pr.CloseWithError(err)
		return SendStats{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/zstd")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		pr.CloseWithError(err)
		return SendStats{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusConflict {
		return SendStats{}, fmt.Errorf("%s %s: %w", method, path, errComplete)
	}
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return SendStats{}, fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(b)))
	}
	return SendStats{RawBytes: raw.Load(), WireBytes: wire.Load(), Duration: time.Since(start)}, nil
}

// HandOver tells the target that the source is paused (early hand-over).
func (c *Client) HandOver(ctx context.Context, uid string) error {
	ctx, cancel := context.WithTimeout(ctx, controlTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.url(fmt.Sprintf("/v1/m/%s/handover", uid)), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("hand-over: %s", resp.Status)
	}
	return nil
}

// AwaitCompaction returns once the target has folded the container's
// pre-copy rounds into its base image.
func (c *Client) AwaitCompaction(ctx context.Context, uid, container string) error {
	ctx, cancel := context.WithTimeout(ctx, readyTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.url(fmt.Sprintf("/v1/m/%s/c/%s/compacted", uid, container)), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return nil
}

// Marker sets READY or FAILED (uncompressed, small body).
func (c *Client) Marker(ctx context.Context, uid, container, marker, reason string) error {
	timeout := controlTimeout
	if marker == "ready" {
		timeout = readyTimeout // the target first folds in the last rounds
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.url(fmt.Sprintf("/v1/m/%s/c/%s/%s", uid, container, marker)), strings.NewReader(reason))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusConflict {
		return fmt.Errorf("marker %s: %w", marker, errComplete)
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("marker %s: %s", marker, resp.Status)
	}
	return nil
}

type countingWriter struct {
	w io.Writer
	n *atomic.Int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n.Add(int64(n))
	return n, err
}
