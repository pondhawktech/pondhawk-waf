#!/usr/bin/env bash
# Builds the libinjection-go oracle (in a golang container, with podman or docker) and runs the differential fuzzer.
# Arguments go to the fuzzer: --count N (default 1,000,000), --seed N, --max-len N, --report file.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
runtime=$(command -v podman || command -v docker || true)
if [[ ! -x "$here/oracle/libinjection-oracle" || "$here/oracle/go.mod" -nt "$here/oracle/libinjection-oracle" || "$here/oracle/main.go" -nt "$here/oracle/libinjection-oracle" ]]; then
  if command -v go >/dev/null; then
    (cd "$here/oracle" && CGO_ENABLED=0 go build -trimpath -o libinjection-oracle .)
  elif [[ -n "$runtime" ]]; then
    "$runtime" run --rm -v "$here/oracle":/w:Z -w /w -e CGO_ENABLED=0 docker.io/library/golang:1.25 \
      go build -trimpath -o libinjection-oracle .
  else
    echo "Needs Go, podman or docker to build the oracle." >&2
    exit 2
  fi
fi
dotnet run --project "$here" --configuration Release -- --oracle "$here/oracle/libinjection-oracle" "$@"
