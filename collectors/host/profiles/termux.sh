# host profile: Android/Termux (no root). READ-ONLY.
"$PREFIX/bin/sshd" -T 2>/dev/null | awk '{k=tolower($1)} k~/^(passwordauthentication|permitrootlogin|kbdinteractiveauthentication)$/{print "sshd."k"="tolower($2)}'
echo "os.name=Android $(getprop ro.build.version.release) (patch $(getprop ro.build.version.security_patch))"
echo "os.security_patch=$(getprop ro.build.version.security_patch)"
echo "pkg.upgradable=$(apt list --upgradable 2>/dev/null | grep -c upgradable)"
echo "pkg.cache_mtime=$(stat -c %Y $PREFIX/var/cache/apt/pkgcache.bin 2>/dev/null)"
echo "uptime_days=$(awk '{print int($1/86400)}' /proc/uptime 2>/dev/null)"
for f in /proc/net/tcp /proc/net/tcp6; do
  [ -r $f ] && awk 'NR>1 && $4=="0A"{split($2,a,":"); printf "listen=%s:%d\n", a[1], strtonum("0x" a[2])}' $f
done | sort -u
ps -eo args 2>/dev/null | grep -E -- '(--pass|--password|htpasswd)' | grep -vc grep | sed 's/^/proc.secret_in_argv_suspects=/'
