// Command deb-custom-extensions hosts support-authored Chromium/Ulaa extensions
// for force-install. It scans a directory of unpacked extension folders, signs
// each into a CRX3, and serves the CRX plus an Omaha update manifest with the
// headers Ulaa needs — the one-line value to drop into the Ulaa Enterprise
// ExtensionInstallForcelist policy is shown on the index page.
package main

import (
	"context"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"deb-custom-extensions/internal/store"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

type server struct {
	reg     *store.Registry
	baseURL string // optional public base URL override
	tmpl    *template.Template
}

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	extDir := flag.String("ext-dir", "extensions", "directory containing one folder per extension")
	keyDir := flag.String("key-dir", "data/keys", "directory where per-extension signing keys are persisted (back this up)")
	baseURL := flag.String("base-url", "", "public base URL e.g. https://ext.example.com (if empty, derived per request)")
	scanInterval := flag.Duration("scan-interval", 15*time.Second, "how often to rescan ext-dir for changes (0 disables)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	reg := store.New(*extDir, *keyDir)
	if err := reg.Scan(); err != nil {
		log.Fatalf("initial scan failed: %v", err)
	}

	s := &server{
		reg:     reg,
		baseURL: strings.TrimRight(*baseURL, "/"),
		tmpl:    template.Must(template.New("index").Parse(indexHTML)),
	}

	if *scanInterval > 0 {
		go func() {
			t := time.NewTicker(*scanInterval)
			defer t.Stop()
			for range t.C {
				if err := reg.Scan(); err != nil {
					log.Printf("rescan error: %v", err)
				}
			}
		}()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") })
	mux.HandleFunc("POST /reload", s.handleReload)
	mux.HandleFunc("GET /updates/{file}", s.handleUpdates)
	mux.HandleFunc("GET /crx/{file}", s.handleCRX)

	srv := &http.Server{Addr: *addr, Handler: logRequests(mux), ReadHeaderTimeout: 10 * time.Second}

	go func() {
		log.Printf("deb-custom-extensions %s serving extensions from %q (keys in %q) on %s", version, *extDir, *keyDir, *addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	log.Println("shut down")
}

func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
	_ = s.reg.Scan() // pick up freshly-dropped folders on view
	base := s.baseFor(r)

	type row struct {
		Name, ID, Version, UpdateURL, CRXURL, Policy, Err string
		Valid                                             bool
	}
	var rows []row
	for _, e := range s.reg.List() {
		rw := row{Name: e.Name, ID: e.ID, Version: e.Version, Valid: e.Valid, Err: e.Err}
		if e.Valid {
			rw.UpdateURL = fmt.Sprintf("%s/updates/%s.xml", base, e.Name)
			rw.CRXURL = fmt.Sprintf("%s/crx/%s.crx", base, e.Name)
			rw.Policy = e.ID + ";" + rw.UpdateURL
		}
		rows = append(rows, rw)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.Execute(w, rows); err != nil {
		log.Printf("render index: %v", err)
	}
}

func (s *server) handleReload(w http.ResponseWriter, _ *http.Request) {
	if err := s.reg.Scan(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	io.WriteString(w, "reloaded\n")
}

func (s *server) handleUpdates(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSuffix(r.PathValue("file"), ".xml")
	ext, ok := s.lookup(name)
	if !ok {
		http.NotFound(w, r)
		return
	}
	codebase := fmt.Sprintf("%s/crx/%s.crx", s.baseFor(r), name)
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	io.WriteString(w, updateManifest(ext.ID, ext.Version, codebase))
}

func (s *server) handleCRX(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSuffix(r.PathValue("file"), ".crx")
	ext, ok := s.lookup(name)
	if !ok {
		http.NotFound(w, r)
		return
	}
	body := ext.CRX()
	w.Header().Set("Content-Type", "application/x-chrome-extension")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(body)
}

// lookup resolves a URL slug to a valid extension, rejecting unsafe names.
func (s *server) lookup(name string) (*store.Extension, bool) {
	if !validName(name) {
		return nil, false
	}
	ext, ok := s.reg.Get(name)
	if !ok || !ext.Valid {
		return nil, false
	}
	return ext, true
}

func (s *server) baseFor(r *http.Request) string {
	if s.baseURL != "" {
		return s.baseURL
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if p := r.Header.Get("X-Forwarded-Proto"); p != "" {
		scheme = p
	}
	return scheme + "://" + r.Host
}

// updateManifest renders the Omaha v2 update response that ExtensionInstallForcelist
// points at via the update_url half of "<id>;<update_url>".
func updateManifest(id, version, codebase string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<gupdate xmlns="http://www.google.com/update2/response" protocol="2.0">
  <app appid="%s">
    <updatecheck codebase="%s" version="%s" />
  </app>
</gupdate>
`, id, template.HTMLEscapeString(codebase), template.HTMLEscapeString(version))
}

// validName guards path/slug values used to build URLs and look up folders.
func validName(name string) bool {
	if name == "" || strings.Contains(name, "..") {
		return false
	}
	for _, c := range name {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-' || c == '_' || c == '.':
		default:
			return false
		}
	}
	return true
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}

const indexHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Ulaa custom extensions</title>
<style>
 body{font:14px/1.55 system-ui,sans-serif;margin:2rem auto;max-width:60rem;color:#1a1a1a;padding:0 1rem}
 h1{font-size:1.4rem}
 .ext{border:1px solid #ddd;border-radius:8px;padding:1rem 1.25rem;margin:1rem 0}
 .ext.invalid{border-color:#e0b4b4;background:#fdf6f6}
 .name{font-weight:600;font-size:1.05rem}
 .id{font-family:ui-monospace,monospace;color:#555;margin-top:.2rem}
 code,.policy{font-family:ui-monospace,monospace}
 .policy{display:block;background:#f5f5f5;border:1px solid #e3e3e3;border-radius:6px;padding:.6rem .7rem;margin:.35rem 0;word-break:break-all}
 .label{color:#777;font-size:.8rem;text-transform:uppercase;letter-spacing:.04em;margin-top:.7rem}
 .err{color:#a33}
 a{color:#1558d6;word-break:break-all}
 .ok{color:#2a7}
</style>
</head>
<body>
<h1>Ulaa custom extensions</h1>
<p>Paste the <strong>policy value</strong> into the Ulaa Enterprise dashboard
(<code>ExtensionInstallForcelist</code>). The managed browser fetches the update
manifest, downloads the signed CRX, and force-installs it.</p>
{{if not .}}<p><em>No extensions found yet. Drop an unpacked extension folder into
the extensions directory and refresh.</em></p>{{end}}
{{range .}}
<div class="ext {{if not .Valid}}invalid{{end}}">
  <div class="name">{{.Name}} {{if .Valid}}<span class="ok">&#9679;</span>{{else}}<span class="err">&#9679; invalid</span>{{end}}</div>
  {{if .Valid}}
    <div class="id">ID {{.ID}} &nbsp;&middot;&nbsp; version {{.Version}}</div>
    <div class="label">Policy value &mdash; ExtensionInstallForcelist</div>
    <code class="policy">{{.Policy}}</code>
    <div class="label">Update manifest</div>
    <div><a href="{{.UpdateURL}}">{{.UpdateURL}}</a></div>
    <div class="label">CRX</div>
    <div><a href="{{.CRXURL}}">{{.CRXURL}}</a></div>
  {{else}}
    <div class="err">{{.Err}}</div>
  {{end}}
</div>
{{end}}
</body>
</html>
`
