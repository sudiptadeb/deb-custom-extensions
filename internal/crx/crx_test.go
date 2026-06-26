package crx

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestKeyAndIDAreStable(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "k.pem")

	key1, err := LoadOrCreateKey(keyPath) // generates + persists
	if err != nil {
		t.Fatal(err)
	}
	key2, err := LoadOrCreateKey(keyPath) // reloads the same key
	if err != nil {
		t.Fatal(err)
	}

	id1, err := ExtensionID(key1)
	if err != nil {
		t.Fatal(err)
	}
	id2, err := ExtensionID(key2)
	if err != nil {
		t.Fatal(err)
	}
	if id1 != id2 {
		t.Fatalf("extension ID not stable across reloads: %q != %q", id1, id2)
	}
	if len(id1) != 32 {
		t.Fatalf("extension ID must be 32 chars, got %d (%q)", len(id1), id1)
	}
	for _, c := range id1 {
		if c < 'a' || c > 'p' {
			t.Fatalf("extension ID must be a-p only, got %q", id1)
		}
	}
}

func TestPackCRX3IsValidAndVerifiable(t *testing.T) {
	dir := t.TempDir()
	manifest := `{"manifest_version":3,"name":"test","version":"1.2.3"}`
	mustWrite(t, filepath.Join(dir, "manifest.json"), manifest)
	mustWrite(t, filepath.Join(dir, "rules.json"), "[]")
	mustWrite(t, filepath.Join(dir, "key.pem"), "THIS-MUST-NOT-BE-PACKAGED")
	mustWrite(t, filepath.Join(dir, ".hidden"), "ignore me")

	key, err := LoadOrCreateKey(filepath.Join(t.TempDir(), "k.pem"))
	if err != nil {
		t.Fatal(err)
	}

	crxBytes, err := Pack(dir, key, map[string]bool{"key.pem": true})
	if err != nil {
		t.Fatal(err)
	}

	zipData := verifyCRX(t, crxBytes, key)

	zr, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		t.Fatalf("embedded payload is not a valid zip: %v", err)
	}
	names := map[string]bool{}
	for _, f := range zr.File {
		names[f.Name] = true
	}
	if !names["manifest.json"] || !names["rules.json"] {
		t.Fatalf("zip missing expected files, has: %v", names)
	}
	if names["key.pem"] {
		t.Fatal("signing key was leaked into the packaged extension")
	}
	if names[".hidden"] {
		t.Fatal("dotfile should be excluded from the package")
	}
}

// verifyCRX validates the CRX3 container and signature the way a Chromium client
// would, and returns the embedded zip payload.
func verifyCRX(t *testing.T, crxBytes []byte, key *rsa.PrivateKey) []byte {
	t.Helper()
	if len(crxBytes) < 12 || string(crxBytes[:4]) != "Cr24" {
		t.Fatalf("bad magic: %q", crxBytes[:min(4, len(crxBytes))])
	}
	if v := binary.LittleEndian.Uint32(crxBytes[4:8]); v != 3 {
		t.Fatalf("unexpected CRX version: %d", v)
	}
	hlen := binary.LittleEndian.Uint32(crxBytes[8:12])
	if int(12+hlen) > len(crxBytes) {
		t.Fatal("header length exceeds file")
	}
	header := crxBytes[12 : 12+hlen]
	zipData := crxBytes[12+hlen:]

	hf, err := readProtoFields(header)
	if err != nil {
		t.Fatalf("parse header: %v", err)
	}
	proof, err := readProtoFields(hf[2][0])
	if err != nil {
		t.Fatalf("parse key proof: %v", err)
	}
	pub := proof[1][0]
	sig := proof[2][0]
	signedHeader := hf[10000][0]

	signedFields, err := readProtoFields(signedHeader)
	if err != nil {
		t.Fatalf("parse signed header: %v", err)
	}
	gotID := signedFields[1][0]
	sum := sha256.Sum256(pub)
	if !bytes.Equal(gotID, sum[:16]) {
		t.Fatal("crx_id does not match SHA-256(public key)[:16]")
	}

	wantPub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if !bytes.Equal(pub, wantPub) {
		t.Fatal("embedded public key does not match signing key")
	}

	var toSign bytes.Buffer
	toSign.Write([]byte("CRX3 SignedData\x00"))
	var sz [4]byte
	binary.LittleEndian.PutUint32(sz[:], uint32(len(signedHeader)))
	toSign.Write(sz[:])
	toSign.Write(signedHeader)
	toSign.Write(zipData)
	digest := sha256.Sum256(toSign.Bytes())

	parsedPub, err := x509.ParsePKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("parse embedded public key: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(parsedPub.(*rsa.PublicKey), crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("CRX signature failed verification: %v", err)
	}
	return zipData
}

// readProtoFields parses a protobuf message consisting solely of
// length-delimited fields and groups their raw contents by field number.
func readProtoFields(b []byte) (map[int][][]byte, error) {
	out := map[int][][]byte{}
	for len(b) > 0 {
		tag, n := binary.Uvarint(b)
		if n <= 0 {
			return nil, errors.New("bad field tag")
		}
		b = b[n:]
		field := int(tag >> 3)
		if tag&7 != 2 {
			return nil, fmt.Errorf("field %d is not length-delimited", field)
		}
		length, n := binary.Uvarint(b)
		if n <= 0 {
			return nil, errors.New("bad field length")
		}
		b = b[n:]
		if uint64(len(b)) < length {
			return nil, errors.New("truncated field")
		}
		out[field] = append(out[field], b[:length])
		b = b[length:]
	}
	return out, nil
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
