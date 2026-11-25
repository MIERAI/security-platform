#!/bin/sh
# Fake exec target for the collector conformance cases. Installed (by the case) as {sandbox}/bin/ssh, /sh, /sudo,
# /powershell; PATH puts that directory first. It never runs what it is given. It records its argument vector and its
# standard input under $FAKE_EXEC/trace/ and replays $FAKE_EXEC/replay/<target>[.sudo].{out,err,sleep,rc}:
#   target: ssh -> the host argument (options -o -F -i -p -l -J take a value); anything else -> local-<program name>
#   .sudo:  ssh only: the remote command starts with `sudo `
#   out/err: printed to stdout/stderr; sleep: seconds to wait AFTER printing (a script that hangs); rc: exit status
# A missing replay file means: nothing printed, no wait, exit 0. POSIX sh; runs only cat, mkdir and sleep.
set -u
d=${FAKE_EXEC:?FAKE_EXEC is not set}
me=${0##*/}
target=
variant=
if [ "$me" = ssh ]; then
  skip=
  ended=
  for a in "$@"; do
    if [ -n "$skip" ]; then skip=; continue; fi
    if [ -z "$ended" ]; then
      case $a in
        --) ended=1; continue ;;
        -o|-F|-i|-p|-l|-J) skip=1; continue ;;
        -*) continue ;;
      esac
    fi
    if [ -z "$target" ]; then target=$a; continue; fi
    case $a in sudo\ *) variant=.sudo ;; esac
  done
else
  target=local-$me
fi
[ -n "$target" ] || { echo "fake exec: no target in: $*" >&2; exit 255; }
mkdir -p "$d/trace"
printf '%s\n' "$@" > "$d/trace/$target$variant.argv"
cat > "$d/trace/$target$variant.stdin"
r=$d/replay/$target$variant
[ -e "$r.rc" ] || [ -e "$r.out" ] || [ -e "$r.err" ] || r=$d/replay/$target
[ -f "$r.out" ] && cat "$r.out"
[ -f "$r.err" ] && cat "$r.err" >&2
[ -f "$r.sleep" ] && sleep "$(cat "$r.sleep")"
rc=0
[ -f "$r.rc" ] && rc=$(cat "$r.rc")
exit "$rc"
