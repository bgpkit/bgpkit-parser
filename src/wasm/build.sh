#!/usr/bin/env bash
#
# Build bgpkit-parser WASM package for all three targets (nodejs, bundler, web)
# and assemble a single publishable npm package in ./pkg.
#
# Usage:
#   cd <repo-root>
#   bash src/wasm/build.sh
#
# Prerequisites:
#   - wasm-pack: cargo install wasm-pack
#   - wasm32-unknown-unknown target: rustup target add wasm32-unknown-unknown
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

WASM_DIR="src/wasm/js"
OUT_DIR="$REPO_ROOT/pkg"

echo "==> Building nodejs target..."
wasm-pack build --target nodejs --no-default-features --features wasm
mv pkg pkg-nodejs

echo "==> Building bundler target..."
wasm-pack build --target bundler --no-default-features --features wasm
mv pkg pkg-bundler

echo "==> Building web target..."
wasm-pack build --target web --no-default-features --features wasm
mv pkg pkg-web

echo "==> Assembling package..."
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR/nodejs" "$OUT_DIR/bundler" "$OUT_DIR/web"

# nodejs target: main glue + wasm binary
cp pkg-nodejs/bgpkit_parser.js         "$OUT_DIR/nodejs/"
cp pkg-nodejs/bgpkit_parser_bg.wasm    "$OUT_DIR/nodejs/"
cp pkg-nodejs/bgpkit_parser_bg.wasm.d.ts "$OUT_DIR/nodejs/" 2>/dev/null || true

# bundler target: main glue + bg bindings + wasm binary
cp pkg-bundler/bgpkit_parser.js        "$OUT_DIR/bundler/"
cp pkg-bundler/bgpkit_parser_bg.js     "$OUT_DIR/bundler/"
cp pkg-bundler/bgpkit_parser_bg.wasm   "$OUT_DIR/bundler/"
cp pkg-bundler/bgpkit_parser_bg.wasm.d.ts "$OUT_DIR/bundler/" 2>/dev/null || true
cp pkg-bundler/bgpkit_parser.d.ts      "$OUT_DIR/bundler/" 2>/dev/null || true

# web target: main glue + wasm binary (no _bg.js for web target)
cp pkg-web/bgpkit_parser.js            "$OUT_DIR/web/"
cp pkg-web/bgpkit_parser_bg.wasm       "$OUT_DIR/web/"
cp pkg-web/bgpkit_parser_bg.wasm.d.ts  "$OUT_DIR/web/" 2>/dev/null || true
cp pkg-web/bgpkit_parser.d.ts          "$OUT_DIR/web/" 2>/dev/null || true

# JS wrappers and types
cp "$WASM_DIR/index.js"    "$OUT_DIR/"
cp "$WASM_DIR/index.mjs"   "$OUT_DIR/"
cp "$WASM_DIR/index.d.ts"  "$OUT_DIR/"
cp "$WASM_DIR/web.mjs"     "$OUT_DIR/"
cp "$WASM_DIR/web.d.ts"    "$OUT_DIR/"
cp "$WASM_DIR/package.json" "$OUT_DIR/"

# README for npm (displayed on npmjs.com)
cp "$REPO_ROOT/src/wasm/README.md" "$OUT_DIR/"

# Cleanup temp directories
rm -rf pkg-nodejs pkg-bundler pkg-web

echo "==> Done. Package ready in $OUT_DIR/"
echo ""
echo "To publish:"
echo "  cd pkg && npm publish"
