# host profile: Android/Termux (no root). READ-ONLY. sp_probe/sp_lines: probe.sh. Package probes run LAST.
T=$SP_PROBE_TIMEOUT
sp_lines sshd $T '"$PREFIX/bin/sshd" -T 2>/dev/null | awk "{k=tolower(\$1)} k~/^(passwordauthentication|permitrootlogin|kbdinteractiveauthentication)\$/{print \"sshd.\"k\"=\"tolower(\$2)}"'
echo "os.name=Android $(getprop ro.build.version.release) (patch $(getprop ro.build.version.security_patch))"
echo "os.security_patch=$(getprop ro.build.version.security_patch)"
echo "uptime_days=$(awk '{print int($1/86400)}' /proc/uptime 2>/dev/null)"
sp_lines listen $T 'for f in /proc/net/tcp /proc/net/tcp6; do
  [ -r $f ] && awk "NR>1 && \$4==\"0A\"{split(\$2,a,\":\"); printf \"listen=%s:%d\\n\", a[1], strtonum(\"0x\" a[2])}" $f
done | sort -u'
sp_probe proc.secret_in_argv_suspects $T 'ps -eo args 2>/dev/null | grep -E -- "(--pass|--password|htpasswd)" | grep -vc grep'
sp_probe pkg.cache_mtime $T 'stat -c %Y $PREFIX/var/cache/apt/pkgcache.bin 2>/dev/null'
sp_probe pkg.upgradable $SP_PROBE_SLOW_TIMEOUT 'apt list --upgradable 2>/dev/null | grep -c upgradable'
