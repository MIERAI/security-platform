# host profile: linux (systemd distros). READ-ONLY. Output: key=value lines. Uses `sudo -n` (never prompts).
# sp_probe/sp_lines: probe.sh (per-command limits). Package-manager probes run LAST with the slow limit.
S="sudo -n"; T=$SP_PROBE_TIMEOUT
sp_lines sshd $T '$S sshd -T 2>/dev/null | awk "{k=tolower(\$1)} k~/^(passwordauthentication|permitrootlogin|kbdinteractiveauthentication|pubkeyauthentication|permitemptypasswords|x11forwarding|maxauthtries)\$/{print \"sshd.\"k\"=\"tolower(\$2)}"'
. /etc/os-release 2>/dev/null; echo "os.name=$PRETTY_NAME"; echo "os.kernel=$(uname -r)"
test -f /var/run/reboot-required && echo reboot_required=yes || echo reboot_required=no
echo "uptime_days=$(awk '{print int($1/86400)}' /proc/uptime)"
sp_probe fw.ufw $T '$S ufw status 2>/dev/null | head -1 | awk "{print \$NF}"'
sp_probe fw.nft_input_policy $T '$S nft list chain inet filter input 2>/dev/null | grep -o "policy [a-z]*" | head -1 | cut -d" " -f2'
sp_probe fw.iptables_input_policy $T '$S iptables -S INPUT 2>/dev/null | awk "/^-P INPUT/{print \$3}"'
sp_probe disk.crypt_devices $T 'lsblk -rno TYPE 2>/dev/null | grep -c crypt'
sp_probe audit.auditd $T 'systemctl is-active auditd 2>/dev/null'
sp_probe audit.fail2ban $T 'systemctl is-active fail2ban 2>/dev/null'
sp_lines listen $T '$S ss -Htlnp 2>/dev/null | awk "{split(\$6,a,\"\\\"\"); print \"listen=\"\$4\" \"a[2]}" | sort -u'
if command -v apt >/dev/null; then
  sp_probe pkg.auto_updates $T 'grep -hs "Unattended-Upgrade \"1\"" /etc/apt/apt.conf.d/20auto-upgrades >/dev/null && echo yes || echo no'
  sp_probe pkg.cache_mtime $T 'stat -c %Y /var/cache/apt/pkgcache.bin 2>/dev/null'
  sp_probe pkg.count $T 'dpkg-query -W 2>/dev/null | wc -l'
  sp_probe pkg.upgradable $SP_PROBE_SLOW_TIMEOUT 'apt list --upgradable 2>/dev/null | grep -c upgradable'
  sp_probe pkg.security_upgradable $SP_PROBE_SLOW_TIMEOUT 'apt list --upgradable 2>/dev/null | grep -c -- -security'
fi
