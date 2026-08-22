#!/usr/bin/env bash
#
# Push this Worker's secrets from a local, gitignored file to Cloudflare.
#
#   scripts/push-secrets.sh production     # reads .secrets.production
#   scripts/push-secrets.sh staging        # reads .secrets.staging  → wrangler --env staging
#
# File format: one KEY=VALUE per line, `#` comments allowed, no quotes needed.
# Values travel to `wrangler secret put` on stdin only: never in argv, never echoed.
# Needs a logged-in wrangler (`pnpm wrangler login`) or CLOUDFLARE_API_TOKEN + CLOUDFLARE_ACCOUNT_ID.
# Works with the bash 3.2 that ships with macOS.
set -euo pipefail

usage() {
  echo "usage: $0 <production|staging>" >&2
  exit 2
}

target="${1:-}"
case "$target" in
  production) wrangler_env=() ;;
  staging) wrangler_env=(--env staging) ;;
  *) usage ;;
esac

cd "$(dirname "$0")/.."
file=".secrets.$target"
if [[ ! -f "$file" ]]; then
  echo "error: $file not found. Create it (it is gitignored) with:" >&2
  echo "  SESSION_KEY=<base64url 32 bytes>   CF_ACCESS_CLIENT_ID=...   CF_ACCESS_CLIENT_SECRET=..." >&2
  exit 1
fi

# Must match `secrets.required` in wrangler.jsonc.
required=(SESSION_KEY CF_ACCESS_CLIENT_ID CF_ACCESS_CLIENT_SECRET)

names=()
values=()
while IFS= read -r line || [[ -n "$line" ]]; do
  line="${line%$'\r'}"
  [[ -z "$line" || "$line" == \#* ]] && continue
  if [[ "$line" != *=* ]]; then
    echo "error: $file: expected KEY=VALUE, got a line without '='" >&2
    exit 1
  fi
  key="${line%%=*}"
  value="${line#*=}"
  if [[ ! "$key" =~ ^[A-Z][A-Z0-9_]*$ ]]; then
    echo "error: $file: bad key name '$key'" >&2
    exit 1
  fi
  names+=("$key")
  values+=("$value")
done <"$file"

lookup() {
  local i
  for i in "${!names[@]}"; do
    if [[ "${names[$i]}" == "$1" ]]; then
      printf '%s' "${values[$i]}"
      return 0
    fi
  done
  return 1
}

for key in "${required[@]}"; do
  if [[ -z "$(lookup "$key" || true)" ]]; then
    echo "error: $key is missing or empty in $file" >&2
    exit 1
  fi
done

# SESSION_KEY: base64url of exactly 32 bytes (AES-256-GCM). Count the bytes without printing them.
session_key="$(lookup SESSION_KEY)"
if [[ ! "$session_key" =~ ^[A-Za-z0-9_-]+$ ]]; then
  echo "error: SESSION_KEY is not base64url (no padding, alphabet A-Z a-z 0-9 - _)" >&2
  exit 1
fi
pad=$(((4 - ${#session_key} % 4) % 4))
byte_count="$( (printf '%s' "$session_key" | tr -- '-_' '+/' && printf '%*s' "$pad" '' | tr ' ' '=') | (openssl base64 -d -A 2>/dev/null || true) | wc -c | tr -d ' ')"
if [[ "$byte_count" != "32" ]]; then
  echo "error: SESSION_KEY decodes to $byte_count bytes, expected 32" >&2
  exit 1
fi

echo "pushing ${#names[@]} secret(s) to afixo-api ($target)"
for i in "${!names[@]}"; do
  echo "  ${names[$i]}"
  printf '%s' "${values[$i]}" | pnpm exec wrangler secret put "${names[$i]}" ${wrangler_env[@]+"${wrangler_env[@]}"}
done

echo "verifying with 'wrangler secret list'"
pnpm exec wrangler secret list ${wrangler_env[@]+"${wrangler_env[@]}"}
