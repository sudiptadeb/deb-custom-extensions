// Package store scans a directory of unpacked extensions, packages each valid
// one into a signed CRX3, and caches the result. Re-scanning only repacks an
// extension when its source files actually change.
package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"deb-custom-extensions/internal/crx"
)

// Extension is the packaged result for a single source folder. Once published
// by Scan it is treated as immutable; a rebuild replaces it with a new value.
type Extension struct {
	Name    string // source folder name; also the URL slug
	ID      string // 32-char extension ID (empty when invalid)
	Version string // version string from manifest.json
	Valid   bool   // true when the folder packaged successfully
	Err     string // human-readable reason when not Valid

	crx []byte // signed CRX3 bytes
	fp  string // fingerprint of the source files, for change detection
}

// CRX returns the signed CRX3 bytes (nil for invalid extensions).
func (e *Extension) CRX() []byte { return e.crx }

// Registry holds the packaged extensions discovered under extDir. Signing keys
// are persisted under keyDir, one PEM file per extension, so IDs stay stable.
type Registry struct {
	extDir string
	keyDir string

	mu   sync.Mutex
	exts map[string]*Extension
}

// New returns a Registry. Call Scan before serving.
func New(extDir, keyDir string) *Registry {
	return &Registry{extDir: extDir, keyDir: keyDir, exts: map[string]*Extension{}}
}

// Scan re-reads the extensions directory, building any extension whose source
// changed and dropping any whose folder was removed. It is safe for concurrent
// use and cheap when nothing changed.
func (r *Registry) Scan() error {
	entries, err := os.ReadDir(r.extDir)
	if err != nil {
		return fmt.Errorf("store: read %s: %w", r.extDir, err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	present := make(map[string]bool)
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		present[entry.Name()] = true
		r.build(entry.Name())
	}
	for name := range r.exts {
		if !present[name] {
			delete(r.exts, name)
		}
	}
	return nil
}

// build (re)packages a single extension. Caller must hold r.mu.
func (r *Registry) build(name string) {
	dir := filepath.Join(r.extDir, name)

	fp, err := fingerprint(dir)
	if err != nil {
		r.exts[name] = &Extension{Name: name, Err: err.Error()}
		return
	}
	if cur, ok := r.exts[name]; ok && cur.Valid && cur.fp == fp {
		return // unchanged since last successful build
	}

	ext := &Extension{Name: name, fp: fp}
	defer func() { r.exts[name] = ext }()

	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		ext.Err = "missing or unreadable manifest.json: " + err.Error()
		return
	}
	var manifest struct {
		Version         string `json:"version"`
		ManifestVersion int    `json:"manifest_version"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		ext.Err = "invalid manifest.json: " + err.Error()
		return
	}
	if manifest.Version == "" {
		ext.Err = `manifest.json is missing a "version"`
		return
	}
	ext.Version = manifest.Version

	key, err := crx.LoadOrCreateKey(filepath.Join(r.keyDir, name+".pem"))
	if err != nil {
		ext.Err = err.Error()
		return
	}
	id, err := crx.ExtensionID(key)
	if err != nil {
		ext.Err = err.Error()
		return
	}
	ext.ID = id

	packed, err := crx.Pack(dir, key, map[string]bool{"key.pem": true})
	if err != nil {
		ext.Err = "packaging failed: " + err.Error()
		return
	}
	ext.crx = packed
	ext.Valid = true
}

// List returns all known extensions sorted by name.
func (r *Registry) List() []*Extension {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*Extension, 0, len(r.exts))
	for _, e := range r.exts {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Get returns the extension for a folder name.
func (r *Registry) Get(name string) (*Extension, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.exts[name]
	return e, ok
}

// fingerprint hashes the relative path, size and mtime of every packaged file
// in dir so an unchanged folder is detected without repacking. The signing key
// and dotfiles are excluded, matching what crx.Pack archives.
func fingerprint(dir string) (string, error) {
	var items []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		base := filepath.Base(rel)
		if strings.HasPrefix(base, ".") || base == "key.pem" {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		items = append(items, fmt.Sprintf("%s|%d|%d", filepath.ToSlash(rel), info.Size(), info.ModTime().UnixNano()))
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Strings(items)
	h := sha256.New()
	for _, it := range items {
		h.Write([]byte(it))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
