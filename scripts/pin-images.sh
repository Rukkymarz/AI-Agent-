#!/usr/bin/env bash
# Resolve every compose image tag to an immutable @sha256 digest and print .env overrides.
set -euo pipefail
cd "$(dirname "$0")/.."
docker compose config --images | sort -u | while read -r img; do
  [[ "$img" == aicompany-os/* ]] && continue
  docker pull -q "$img" >/dev/null
  echo "$img -> $(docker inspect --format '{{index .RepoDigests 0}}' "$img")"
done
