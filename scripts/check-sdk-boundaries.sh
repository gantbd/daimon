#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

tree=$(cargo tree -p daimon-sdk-embedded --edges normal --depth 1 --locked --offline)
if [[ $(printf '%s\n' "$tree" | wc -l | tr -d ' ') != 2 ]] \
  || ! printf '%s\n' "$tree" | rg -q 'daimon-harness'; then
  printf '%s\n' "$tree" >&2
  echo 'Daimon embedded SDK escaped its harness-only closure' >&2
  exit 1
fi

echo 'Daimon embedded SDK dependency closure verified'
