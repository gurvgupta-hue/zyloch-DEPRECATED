#!/usr/bin/env bash
#
# Give this developer's backend its own BullMQ key namespace.
#
# WHY THIS EXISTS
#   Every developer runs their own backend on their own VM, but all of those
#   backends point at ONE shared Redis. A BullMQ queue name is global to the
#   Redis instance behind it, so `installation-summary` is a single shared
#   mailbox: a job enqueued by one developer's backend can be popped by any
#   other developer's idle worker, whichever gets there first.
#
#   When that happens the receiving worker cannot mint an installation token —
#   the installation belongs to a different GitHub App — so GitHub answers 404,
#   the failure is recorded against the wrong developer's database, and the
#   originating backend's job document sits on `pending` until the frontend
#   gives up ten minutes later. It is a race, so it fails intermittently.
#
# WHY IT IS A SCRIPT AND NOT COMMITTED CODE
#   Production runs a single deployment whose replicas all share one
#   GITHUB_APP_ID, so they would all compute the same prefix and share one
#   queue anyway — the namespace changes nothing there. It is dev-only, so the
#   edits stay out of the repo and get applied locally on demand instead.
#
# USAGE
#   scripts/dev-queue-isolation.sh            # apply (default)
#   scripts/dev-queue-isolation.sh status     # report what is applied
#   scripts/dev-queue-isolation.sh revert     # remove every trace
#
#   Safe to run repeatedly — applying twice is a no-op. Restart the backend
#   afterwards; the prefix is read once at startup.
#
set -euo pipefail

# Every injected line carries this marker, which is what makes `revert` exact
# and `apply` idempotent: reverting is "delete lines bearing the marker", not a
# reverse patch that rots the moment the surrounding code is edited.
readonly MARKER='DEV-QUEUE-ISOLATION'

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly BACKEND_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

readonly QUEUE_FILE="${BACKEND_DIR}/queues/summaryQueue.js"
readonly WORKER_FILE="${BACKEND_DIR}/workers/summaryWorker.js"
readonly NS_FILE="${BACKEND_DIR}/queues/namespace.js"

readonly C_OK=$'\033[32m'
readonly C_WARN=$'\033[33m'
readonly C_ERR=$'\033[31m'
readonly C_DIM=$'\033[2m'
readonly C_OFF=$'\033[0m'

info() { printf '%s\n' "$*"; }
ok()   { printf '%s✓%s %s\n' "$C_OK" "$C_OFF" "$*"; }
warn() { printf '%s!%s %s\n' "$C_WARN" "$C_OFF" "$*"; }
die()  { printf '%sERROR%s %s\n' "$C_ERR" "$C_OFF" "$*" >&2; exit 1; }

# --------------------------------------------------------------------------
# Guards
# --------------------------------------------------------------------------

# The namespace is a workaround for a shared *development* Redis. Applying it
# to a production checkout would silently repoint prod at a fresh, empty set of
# Redis keys and strand every job already queued under the old ones.
if [[ "${NODE_ENV:-}" == "production" ]]; then
  die "NODE_ENV=production — refusing to patch a production checkout."
fi

for f in "$QUEUE_FILE" "$WORKER_FILE"; do
  [[ -f "$f" ]] || die "Expected file not found: $f (run this from the Zyloch-Backend checkout)"
done

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

is_patched() { grep -qF "$MARKER" "$1" 2>/dev/null; }

# --------------------------------------------------------------------------
# Ignoring the generated module
#
# The rule goes in .git/info/exclude, NOT .gitignore. .gitignore is a tracked
# file, so putting it there would itself be a committed trace of a dev-only
# workaround. info/exclude is per-clone and never leaves this machine.
# --------------------------------------------------------------------------

git_exclude_file() {
  local gitdir
  gitdir="$(git -C "$BACKEND_DIR" rev-parse --git-common-dir 2>/dev/null)" \
    || gitdir="$(git -C "$BACKEND_DIR" rev-parse --git-dir 2>/dev/null)" \
    || return 1
  # rev-parse may hand back a path relative to BACKEND_DIR.
  case "$gitdir" in
    /*) ;;
     *) gitdir="$(cd "$BACKEND_DIR" && cd "$gitdir" && pwd)" || return 1 ;;
  esac
  printf '%s/info/exclude' "$gitdir"
}

# Exclude patterns are matched from the repo root, not from this directory.
ns_repo_path() {
  local top
  top="$(git -C "$BACKEND_DIR" rev-parse --show-toplevel 2>/dev/null)" || return 1
  printf '%s' "${NS_FILE#"$top"/}"
}

is_excluded() {
  local ex; ex="$(git_exclude_file)" || return 1
  [[ -f "$ex" ]] && grep -qF "$MARKER" "$ex"
}

add_exclude() {
  local ex path
  if ! ex="$(git_exclude_file)" || ! path="$(ns_repo_path)"; then
    warn "Not a git checkout — skipped the ignore rule."
    warn "queues/namespace.js will show up as an untracked file."
    return 0
  fi

  if is_excluded; then
    info "${C_DIM}· .git/info/exclude already covers it.${C_OFF}"
    return 0
  fi

  mkdir -p "$(dirname "$ex")"
  # A file with no trailing newline would otherwise swallow our line into the last one.
  [[ -s "$ex" && -n "$(tail -c 1 "$ex")" ]] && printf '\n' >> "$ex"
  printf '%s\n%s\n' "# ${MARKER} — generated locally, must never be committed." "$path" >> "$ex"
  ok ".git/info/exclude now hides ${path}."
}

remove_exclude() {
  local ex tmp
  ex="$(git_exclude_file)" || return 0
  [[ -f "$ex" ]] || return 0
  is_excluded || return 0

  tmp="$(mktemp)"
  # Drop the marker comment and the path line that follows it.
  awk -v marker="$MARKER" '
    index($0, marker) { skip = 1; next }
    skip { skip = 0; next }
    { print }
  ' "$ex" > "$tmp"
  cat "$tmp" > "$ex"
  rm -f "$tmp"
  ok ".git/info/exclude entry removed."
}

# Insert PAYLOAD on the line after the first line matching ANCHOR.
# When COPY_INDENT is 1 the anchor's leading whitespace is reused, so injected
# lines line up with the object literal they are joining.
add_line_after() {
  local file="$1" anchor="$2" payload="$3" copy_indent="${4:-0}"
  local tmp
  tmp="$(mktemp)"

  if ! awk -v anchor="$anchor" -v payload="$payload" -v copyindent="$copy_indent" '
        { print }
        !inserted && $0 ~ anchor {
          indent = ""
          if (copyindent == "1") { match($0, /^[[:blank:]]*/); indent = substr($0, 1, RLENGTH) }
          print indent payload
          inserted = 1
        }
        END { if (!inserted) exit 3 }
      ' "$file" > "$tmp"; then
    rm -f "$tmp"
    die "Could not find the anchor /${anchor}/ in ${file#$BACKEND_DIR/}.
      The file has changed shape since this script was written. Fix the anchor
      in scripts/dev-queue-isolation.sh rather than editing the file by hand."
  fi

  cat "$tmp" > "$file"
  rm -f "$tmp"
}

strip_marked_lines() {
  local file="$1" tmp
  tmp="$(mktemp)"
  grep -vF "$MARKER" "$file" > "$tmp" || true
  cat "$tmp" > "$file"
  rm -f "$tmp"
}

# A syntax error here would look like a mysterious boot failure, so prove the
# files still parse before handing control back.
verify_parses() {
  command -v node >/dev/null 2>&1 || { warn "node not on PATH — skipped syntax check."; return 0; }
  local f
  for f in "$QUEUE_FILE" "$WORKER_FILE" "$NS_FILE"; do
    [[ -f "$f" ]] || continue
    node --check "$f" 2>/dev/null || die "Patched file no longer parses: ${f#$BACKEND_DIR/} — run 'revert'."
  done
  ok "Syntax check passed."
}

# --------------------------------------------------------------------------
# namespace.js
# --------------------------------------------------------------------------

write_namespace_module() {
  cat > "$NS_FILE" <<'JS'
/**
 * BullMQ key namespace — GENERATED, DEV ONLY, DO NOT COMMIT.
 *
 * Written by scripts/dev-queue-isolation.sh. Edits here are lost on the next
 * apply; change the script instead.
 *
 * A queue name is global to the Redis instance behind it, and every developer's
 * backend points at the same shared Redis. So a job added by one backend can be
 * popped by any other backend that happens to be idle — whoever gets there
 * first wins, regardless of which one enqueued it.
 *
 * The namespace is DERIVED from GITHUB_APP_ID rather than configured per
 * developer, for two reasons:
 *
 *   1. The App id is precisely what decides whether a job is runnable at all —
 *      only the backend whose App owns the installation can mint its token.
 *      Keying the queue on it means a queue can never hold a job its own workers
 *      are unable to process.
 *   2. Nothing has to be remembered. A config knob that every developer must set
 *      correctly is a config knob that silently reverts to "shared" the first
 *      time someone copies an .env, which is the failure this exists to prevent.
 */

/** Escape hatch for a checkout that must pin its namespace explicitly. */
const OVERRIDE = process.env.QUEUE_NAMESPACE;

function queuePrefix() {
  if (OVERRIDE) return `zyloch:${OVERRIDE}`;

  const appId = process.env.GITHUB_APP_ID;
  if (!appId) {
    // Sharing one namespace is worse than not starting: it corrupts other
    // developers' job state rather than only breaking this one.
    throw new Error(
      'Cannot namespace the job queues: GITHUB_APP_ID is not set (or set QUEUE_NAMESPACE to override).'
    );
  }

  return `zyloch:app-${appId}`;
}

module.exports = { queuePrefix };
JS
}

# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

cmd_apply() {
  info "Applying dev queue isolation in ${BACKEND_DIR}"
  info ""

  write_namespace_module
  ok "queues/namespace.js written."
  add_exclude

  if is_patched "$QUEUE_FILE"; then
    info "${C_DIM}· queues/summaryQueue.js already patched.${C_OFF}"
  else
    add_line_after "$QUEUE_FILE" '^const config = require' \
      "const { queuePrefix } = require('./namespace'); // ${MARKER}"
    # `prefix` MUST match the worker's. A mismatch is silent: the queue accepts
    # jobs onto one set of Redis keys while the worker polls another, so nothing
    # errors and nothing is ever processed.
    add_line_after "$QUEUE_FILE" '^[[:blank:]]*connection,$' \
      "prefix: queuePrefix(), // ${MARKER}" 1
    ok "queues/summaryQueue.js patched."
  fi

  if is_patched "$WORKER_FILE"; then
    info "${C_DIM}· workers/summaryWorker.js already patched.${C_OFF}"
  else
    add_line_after "$WORKER_FILE" '^const connection = require' \
      "const { queuePrefix } = require('../queues/namespace'); // ${MARKER}"
    add_line_after "$WORKER_FILE" '^[[:blank:]]*connection,$' \
      "prefix: queuePrefix(), // ${MARKER}" 1
    ok "workers/summaryWorker.js patched."
  fi

  verify_parses
  info ""
  report_prefix
  info ""
  warn "These edits must NOT be committed. Check 'git status' before you stage."
  info "Restart the backend for the new prefix to take effect."
}

cmd_revert() {
  info "Reverting dev queue isolation in ${BACKEND_DIR}"
  info ""

  local touched=0
  for f in "$QUEUE_FILE" "$WORKER_FILE"; do
    if is_patched "$f"; then
      strip_marked_lines "$f"
      ok "${f#$BACKEND_DIR/} restored."
      touched=1
    else
      info "${C_DIM}· ${f#$BACKEND_DIR/} was not patched.${C_OFF}"
    fi
  done

  if [[ -f "$NS_FILE" ]]; then
    rm -f "$NS_FILE"
    ok "queues/namespace.js removed."
    touched=1
  fi

  if is_excluded; then
    remove_exclude
    touched=1
  fi

  verify_parses
  info ""
  if [[ $touched -eq 1 ]]; then
    info "Back to the committed code. Restart the backend."
    info "${C_DIM}Jobs still sitting under the zyloch:app-* keys will not be picked up.${C_OFF}"
  else
    info "Nothing to do — already clean."
  fi
}

report_prefix() {
  local prefix
  if [[ -n "${QUEUE_NAMESPACE:-}" ]]; then
    prefix="zyloch:${QUEUE_NAMESPACE}"
  elif [[ -n "${GITHUB_APP_ID:-}" ]]; then
    prefix="zyloch:app-${GITHUB_APP_ID}"
  else
    warn "Neither GITHUB_APP_ID nor QUEUE_NAMESPACE is set in this shell."
    info "  That is fine if the backend gets them from Vault at container start."
    info "  If it does not, the backend will refuse to boot with a clear error."
    return 0
  fi
  info "This shell would produce the prefix: ${C_OK}${prefix}${C_OFF}"
  info "${C_DIM}  Redis keys become ${prefix}:installation-summary:*${C_OFF}"
}

cmd_status() {
  info "Dev queue isolation status — ${BACKEND_DIR}"
  info ""

  local applied=0 total=0
  for f in "$QUEUE_FILE" "$WORKER_FILE"; do
    total=$((total + 1))
    if is_patched "$f"; then
      applied=$((applied + 1))
      printf '  %sapplied%s   %s\n' "$C_OK" "$C_OFF" "${f#$BACKEND_DIR/}"
    else
      printf '  %sclean%s     %s\n' "$C_DIM" "$C_OFF" "${f#$BACKEND_DIR/}"
    fi
  done

  if [[ -f "$NS_FILE" ]]; then
    printf '  %spresent%s   queues/namespace.js\n' "$C_OK" "$C_OFF"
  else
    printf '  %smissing%s   queues/namespace.js\n' "$C_DIM" "$C_OFF"
  fi

  if is_excluded; then
    printf '  %signored%s   .git/info/exclude entry\n' "$C_OK" "$C_OFF"
  else
    printf '  %sabsent%s    .git/info/exclude entry\n' "$C_DIM" "$C_OFF"
  fi

  info ""
  # A half-applied state is the one genuinely dangerous outcome: a queue writing
  # under a prefix its worker does not read produces no error at all, just jobs
  # that are never processed.
  if [[ $applied -gt 0 && $applied -lt $total ]]; then
    warn "HALF APPLIED — the queue and worker disagree, so no job will ever run."
    warn "Run 'revert' then apply again."
  elif [[ $applied -eq $total && ! -f "$NS_FILE" ]]; then
    warn "Files are patched but queues/namespace.js is missing — the backend will not boot."
    warn "Run this script again to regenerate it."
  elif [[ $applied -eq $total ]]; then
    report_prefix
  else
    info "Not applied — running the committed code."
  fi
}

case "${1:-apply}" in
  apply|"")        cmd_apply ;;
  revert|remove)   cmd_revert ;;
  status)          cmd_status ;;
  -h|--help|help)  sed -n '2,32p' "${BASH_SOURCE[0]}" | sed 's/^#[[:blank:]]\{0,1\}//' ;;
  *)               die "Unknown command '$1'. Use: apply | revert | status" ;;
esac
