#!/usr/bin/env bash
# Unit tests with the race detector, holding coverage at 75 % or more
set -euo pipefail
go test -race -count=1 -coverprofile=coverage.out ./...
total="$(go tool cover -func=coverage.out | awk '/^total:/ {sub("%", "", $3); print $3}')"
rm -f coverage.out
awk -v t="$total" 'BEGIN { if (t < 75) { print "coverage " t " % is under 75 %"; exit 1 } print "coverage " t " %" }'
