//go:build unix

package runner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// metricsHandler serves GET /metrics (every DIR/*.prom, concatenated, plus security_exporter_files), /healthz and
// /ready, as the reference exporter.
func metricsHandler(dir string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, code := "not found\n", http.StatusNotFound
		switch path, _, _ := strings.Cut(req.URL.RequestURI(), "?"); path {
		case "/healthz", "/ready":
			body, code = "ok\n", http.StatusOK
		case "/metrics":
			body, code = exporterText(dir), http.StatusOK
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(code)
		_, _ = fmt.Fprint(w, body) // the client went away: nothing to do
	})
}

func exporterText(dir string) string {
	files := glob(filepath.Join(dir, "*.prom"))
	var b strings.Builder
	for _, f := range files {
		if data, err := readFile(f, maxPromFile); err == nil {
			b.Write(data)
		}
	}
	fmt.Fprintf(&b, "# TYPE security_exporter_files gauge\nsecurity_exporter_files %d\n", len(files))
	return b.String()
}

// serveMetrics runs the exporter until the process is told to stop.
func serveMetrics(ctx context.Context, env Env, a args) int {
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	srv := &http.Server{Handler: metricsHandler(a.dir), ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second}
	var lc net.ListenConfig
	// all interfaces, as the reference: the exporter runs in a pod or behind the host's firewall
	ln, err := lc.Listen(ctx, "tcp", ":"+strconv.Itoa(a.port))
	if err != nil {
		_, _ = fmt.Fprintf(env.Stderr, "sp runner: %v: %v\n", errNoServer, err) // exit status says it
		return 1
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(sctx); err != nil {
			_, _ = fmt.Fprintf(env.Stderr, "sp runner: serve-metrics: shutdown: %v\n", err) // exiting anyway
		}
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		_, _ = fmt.Fprintf(env.Stderr, "sp runner: %v: %v\n", errNoServer, err) // exit status says it
		return 1
	}
	return ExitOK
}
