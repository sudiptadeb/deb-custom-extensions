// Package crx packages an unpacked Chromium extension directory into a signed
// CRX3 file and derives its stable extension ID.
//
// The CRX3 container is:
//
//	"Cr24"                       (4 bytes, magic)
//	uint32le(3)                  (4 bytes, format version)
//	uint32le(len(header))        (4 bytes)
//	CrxFileHeader                (protobuf)
//	zip archive                  (the extension contents)
//
// The signature inside the header is computed over
//
//	"CRX3 SignedData\x00" || uint32le(len(signedHeader)) || signedHeader || zip
//
// using RSASSA-PKCS1-v1_5 over SHA-256, where signedHeader is a SignedData
// protobuf carrying the 16-byte crx_id. The crx_id is the first 16 bytes of
// SHA-256 over the DER SubjectPublicKeyInfo of the signing key; the textual
// extension ID is those bytes with each nibble mapped 0-15 -> 'a'-'p'.
package crx

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// signatureContext is the 16-byte prefix of the signed payload: the ASCII text
// "CRX3 SignedData" (15 bytes) followed by a single NUL byte.
var signatureContext = []byte("CRX3 SignedData\x00")

// LoadOrCreateKey loads an RSA private key (PKCS#8 PEM) from path, generating
// and persisting a new 2048-bit key if the file does not yet exist. Persisting
// the key keeps the derived extension ID stable across rebuilds and restarts,
// which force-install depends on: change the key and every managed browser sees
// a different extension.
func LoadOrCreateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("crx: %s is not a valid PEM key", path)
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("crx: parse key %s: %w", path, err)
		}
		key, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("crx: %s is not an RSA key", path)
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("crx: read key %s: %w", path, err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("crx: generate key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("crx: marshal key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("crx: mkdir for key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return nil, fmt.Errorf("crx: write key %s: %w", path, err)
	}
	return key, nil
}

// ExtensionID returns the 32-character a-p extension ID derived from the key.
func ExtensionID(key *rsa.PrivateKey) (string, error) {
	id, err := crxID(key)
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	sb.Grow(32)
	for _, b := range id {
		sb.WriteByte('a' + (b >> 4))
		sb.WriteByte('a' + (b & 0x0f))
	}
	return sb.String(), nil
}

// crxID returns the 16-byte raw extension identifier.
func crxID(key *rsa.PrivateKey) ([]byte, error) {
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(pubDER)
	return sum[:16], nil
}

// Pack builds a signed CRX3 from the unpacked extension at dir. Files whose
// path (relative to dir, slash-separated) is present in skip, as well as any
// dotfiles, are excluded from the archive.
func Pack(dir string, key *rsa.PrivateKey, skip map[string]bool) ([]byte, error) {
	zipData, err := zipDir(dir, skip)
	if err != nil {
		return nil, err
	}
	return packCRX3(zipData, key)
}

func packCRX3(zipData []byte, key *rsa.PrivateKey) ([]byte, error) {
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	id, err := crxID(key)
	if err != nil {
		return nil, err
	}

	// signedHeader = SignedData{ crx_id = field 1 }
	signedHeader := protoField(1, id)

	var toSign bytes.Buffer
	toSign.Write(signatureContext)
	toSign.Write(le32(uint32(len(signedHeader))))
	toSign.Write(signedHeader)
	toSign.Write(zipData)

	digest := sha256.Sum256(toSign.Bytes())
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return nil, err
	}

	// AsymmetricKeyProof{ public_key = field 1, signature = field 2 }
	proof := append(protoField(1, pubDER), protoField(2, signature)...)
	// CrxFileHeader{ sha256_with_rsa = field 2, signed_header_data = field 10000 }
	header := append(protoField(2, proof), protoField(10000, signedHeader)...)

	var out bytes.Buffer
	out.WriteString("Cr24")
	out.Write(le32(3))
	out.Write(le32(uint32(len(header))))
	out.Write(header)
	out.Write(zipData)
	return out.Bytes(), nil
}

func zipDir(dir string, skip map[string]bool) ([]byte, error) {
	var rels []string
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
		rel = filepath.ToSlash(rel)
		if strings.HasPrefix(filepath.Base(rel), ".") || skip[rel] {
			return nil
		}
		rels = append(rels, rel)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(rels) == 0 {
		return nil, errors.New("crx: extension directory is empty")
	}
	sort.Strings(rels) // deterministic archive ordering

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, rel := range rels {
		w, err := zw.Create(rel)
		if err != nil {
			return nil, err
		}
		f, err := os.Open(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			return nil, err
		}
		_, err = io.Copy(w, f)
		f.Close()
		if err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// protoField encodes one length-delimited protobuf field (wire type 2).
func protoField(fieldNum int, data []byte) []byte {
	var buf []byte
	buf = appendUvarint(buf, uint64(fieldNum)<<3|2)
	buf = appendUvarint(buf, uint64(len(data)))
	return append(buf, data...)
}

func appendUvarint(buf []byte, v uint64) []byte {
	var tmp [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(tmp[:], v)
	return append(buf, tmp[:n]...)
}

func le32(v uint32) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return b[:]
}
