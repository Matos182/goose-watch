#!/usr/bin/env bash
# Mirror an Ollama library model into a models dir exactly as `ollama pull` would
# (manifest + every layer, each verified by sha256). Workaround for Ollama's parallel
# downloader stalling on WSL2 while plain HTTPS works.
# usage: scripts/fetch-model.sh <name> <tag> <models-dir>
set -euo pipefail
name=$1; tag=$2; dir=$3
reg=https://registry.ollama.ai/v2/library/$name
mkdir -p "$dir/blobs" "$dir/manifests/registry.ollama.ai/library/$name"
man=$(curl -fsS --retry 5 --retry-all-errors -H 'Accept: application/vnd.docker.distribution.manifest.v2+json' "$reg/manifests/$tag")
for d in $(echo "$man" | grep -oE 'sha256:[0-9a-f]{64}'); do
  f="$dir/blobs/sha256-${d#sha256:}"
  if [ -f "$f" ] && [ "$(sha256sum "$f" | cut -d' ' -f1)" = "${d#sha256:}" ]; then echo "have $d"; continue; fi
  curl -fsSL --retry 5 --retry-all-errors -C - -o "$f.partial" "$reg/blobs/$d"
  [ "$(sha256sum "$f.partial" | cut -d' ' -f1)" = "${d#sha256:}" ] || { echo "digest mismatch $d"; exit 1; }
  mv "$f.partial" "$f"; echo "got $d"
done
printf '%s' "$man" > "$dir/manifests/registry.ollama.ai/library/$name/$tag"
echo "mirrored $name:$tag"
