# Probe helpers, prepended by the collector to every POSIX profile. READ-ONLY. POSIX sh only: no `timeout` binary
# (macOS has none, busybox builds differ), no bash-isms; works in dash, bash (also as macOS /bin/sh), busybox ash.
#
#   sp_probe KEY SECONDS 'command'   prints KEY=<first line of the command's stdout>
#   sp_lines KEY SECONDS 'command'   prints the command's stdout lines unchanged (e.g. listen=... lines)
#
# A command still running after SECONDS is stopped (it and its descendants) and reported as `KEY=unknown` plus
# `probe.timeout=KEY` instead of a value; the rest of the output is unaffected. The collector turns that into a
# coverage gap for the checks that read KEY only ("could not check", never a pass).
# SP_PROBE_TIMEOUT / SP_PROBE_SLOW_TIMEOUT are set by the collector from the instance config.
# shellcheck shell=sh
: "${SP_PROBE_TIMEOUT:=20}" "${SP_PROBE_SLOW_TIMEOUT:=90}"
_sp_dir=$(mktemp -d "${TMPDIR:-/tmp}/sp-probe.XXXXXX" 2>/dev/null) || { _sp_dir="${TMPDIR:-/tmp}/sp-probe.$$"; mkdir -p "$_sp_dir"; }
trap 'rm -rf "$_sp_dir"' EXIT

_sp_tree() {  # $1 and every descendant (process table walk: ps -A on macOS/procps/toybox, plain ps on busybox)
  { ps -A -o pid= -o ppid= 2>/dev/null || ps -o pid,ppid 2>/dev/null; } | awk -v root="$1" '
    $1 ~ /^[0-9]+$/ { par[$1] = $2 }
    END { for (p in par) { q = p; n = 0; while (q != root && (q in par) && n++ < 64) q = par[q]; if (q == root) print p } }'
}

# shellcheck disable=SC2086  # $_sp_t is a list of process ids: split on purpose
_sp_stop() {  # TERM the tree, then KILL whatever is left
  _sp_t=$(_sp_tree "$1"); [ -n "$_sp_t" ] || _sp_t=$1
  kill -TERM $_sp_t 2>/dev/null; sleep 1; kill -KILL $_sp_t 2>/dev/null
}

_sp_run() {  # _sp_run SECONDS 'command': stdout in $_sp_dir/out; returns 124 when the time limit stopped it
  case $1 in ''|*[!0-9]*) set -- 20 "$2";; esac   # not a whole number of seconds: the default, never "no limit"
  rm -f "$_sp_dir/out" "$_sp_dir/fired"
  ( eval "$2" ) >"$_sp_dir/out" 2>/dev/null </dev/null &
  _sp_pid=$!
  (
    sleep "$1" & _sp_s=$!
    trap 'kill $_sp_s 2>/dev/null; exit 0' TERM
    wait $_sp_s || exit 0
    : >"$_sp_dir/fired"; _sp_stop "$_sp_pid"
  ) >/dev/null 2>&1 </dev/null &
  _sp_wd=$!
  wait "$_sp_pid" 2>/dev/null
  kill -TERM "$_sp_wd" 2>/dev/null; wait "$_sp_wd" 2>/dev/null
  [ -f "$_sp_dir/fired" ] && return 124
  return 0
}

sp_probe() {
  if _sp_run "$2" "$3"; then printf '%s=%s\n' "$1" "$(head -n 1 "$_sp_dir/out")"
  else printf '%s=unknown\nprobe.timeout=%s\n' "$1" "$1"; fi
}

sp_lines() {
  if _sp_run "$2" "$3"; then cat "$_sp_dir/out"
  else printf 'probe.timeout=%s\n' "$1"; fi
}
