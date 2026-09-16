# Vendored actionlint

This directory contains actionlint 1.7.12 (`rhysd/actionlint` commit
`914e7df21a07ef503a81201c76d2b11c789d3fca`) compiled to Go WebAssembly.
The portable build runs through Node.js on every platform supported by the
adversary runtime. `wasm_exec.js` is from Go 1.25.6.

The embedded checker uses actionlint's public `Linter` API with repository
project loading, ShellCheck, and Pyflakes disabled. The standalone CI lint job
therefore remains useful for those integrations and is not replaced by this
advisory detector.

Rebuild from a clean checkout of the pinned tag:

```sh
mkdir -p cmd/adversary-wasm
cp /path/to/this/main.go cmd/adversary-wasm/main.go
GOOS=js GOARCH=wasm GOTOOLCHAIN=local go build -trimpath \
  -ldflags='-s -w -buildid=' -o actionlint.wasm ./cmd/adversary-wasm
```

The expected SHA-256 of `actionlint.wasm` is
`6df67593685730ca1ec22653e933ee8f77fad463e9ec69911c815b7c9436c910`.
