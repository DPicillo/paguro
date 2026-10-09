// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"paguro.dev/paguro/internal/archive"
	"paguro.dev/paguro/internal/layout"
)

// Throughput of the transfer chain for one pre-copy round: pack, zstd, HTTP
// – into a sink (source side alone) or into the real server (decompress,
// unpack, write). Random pages are the worst case for compression; half-zero
// pages resemble memory that was touched but not filled. To compare with the
// network of a node, build the test binary and run it there:
//
//	go test -c ./internal/agent -o transfer.test
//	./transfer.test -test.run '^$' -test.bench Transfer -test.benchtime 3x
func BenchmarkTransfer(b *testing.B) {
	const size = 256 << 20
	random := make([]byte, size)
	_, _ = rand.Read(random)
	halfZero := make([]byte, size)
	for i := 0; i < size; i += 8192 {
		copy(halfZero[i:i+4096], random[i:i+4096])
	}
	for _, data := range []struct {
		name string
		b    []byte
	}{{"random", random}, {"half-zero", halfZero}} {
		dir := b.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "pages-1.img"), data.b, 0o600); err != nil {
			b.Fatal(err)
		}
		for _, conc := range []int{1, 2, 4} {
			for _, sink := range []string{"discard", "server", "server-tls"} {
				b.Run(fmt.Sprintf("%s/enc=%d/%s", data.name, conc, sink), func(b *testing.B) {
					old := encoderConcurrency
					encoderConcurrency = conc
					defer func() { encoderConcurrency = old }()
					var h http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						_, _ = io.Copy(io.Discard, r.Body)
					})
					if sink != "discard" {
						oldState := layout.StateDir
						layout.StateDir = b.TempDir()
						defer func() { layout.StateDir = oldState }()
						h = (&Server{Token: "t", Log: slog.New(slog.DiscardHandler)}).Handler()
					}
					srv := httptest.NewUnstartedServer(h)
					cl := &Client{Endpoint: srv.Listener.Addr().String(), Token: "t", HTTP: http.DefaultClient}
					if sink == "server-tls" {
						// The agents' mutual TLS, one node certificate per side.
						ca := newTestCA(b)
						srv.TLS = ca.nodeTLS(b, "n2").ServerConfig()
						srv.StartTLS()
						var err error
						if cl, err = NewClient("https://"+srv.Listener.Addr().String(), "t", ca.nodeTLS(b, "n1"), "n2"); err != nil {
							b.Fatal(err)
						}
					} else {
						srv.Start()
					}
					defer srv.Close()
					b.SetBytes(size)
					for i := 0; i < b.N; i++ {
						if _, err := cl.Send(context.Background(), "PUT", fmt.Sprintf("/v1/m/u/c/c/images/%d", i+1), func(w io.Writer) error {
							_, err := archive.Pack(w, dir, archive.PackOptions{})
							return err
						}); err != nil {
							b.Fatal(err)
						}
					}
				})
			}
		}
	}
}
