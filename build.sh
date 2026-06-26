#!/usr/bin/env bash
# Build deb-custom-extensions: format-check, vet, test, then produce static
# binaries for local dev and for EC2 deploy targets (linux amd64 + arm64).
set -euo pipefail

cd "$(dirname "$0")"

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
LDFLAGS="-s -w -X main.version=${VERSION}"
OUT="dist"

echo "==> gofmt"
unformatted="$(gofmt -l .)"
if [ -n "$unformatted" ]; then
  echo "the following files need gofmt:" >&2
  echo "$unformatted" >&2
  exit 1
fi

echo "==> go vet"
go vet ./...

echo "==> go test"
go test ./...

mkdir -p "$OUT"

build() {
  goos="$1"; goarch="$2"
  bin="$OUT/deb-custom-extensions-${goos}-${goarch}"
  echo "==> build ${goos}/${goarch} -> ${bin}"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -trimpath -ldflags "$LDFLAGS" -o "$bin" .
}

echo "==> build host"
CGO_ENABLED=0 go build -trimpath -ldflags "$LDFLAGS" -o "$OUT/deb-custom-extensions" .

# EC2 deploy targets: x86_64 and Graviton/arm64.
build linux amd64
build linux arm64

echo "==> done (version ${VERSION})"
ls -lh "$OUT"
