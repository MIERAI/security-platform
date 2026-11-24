# host profile: linux (systemd distros). READ-ONLY. Output: key=value lines. Uses `sudo -n` (never prompts).
S="sudo -n"
$S sshd -T 2>/dev/null | awk '{k=tolower($1)} k~/^(passwordauthentication|permitrootlogin|kbdinteractiveauthentication|pubkeyauthentication|permitemptypasswords|x11forwarding|maxauthtries)$/{print "sshd."k"="tolower($2)}'
. /etc/os-release 2>/dev/null; echo "os.name=$PRETTY_NAME"; echo "os.kernel=$(uname -r)"
if command -v apt >/dev/null; then
  echo "pkg.upgradable=$(apt list --upgradable 2>/dev/null | grep -c upgradable)"
  echo "pkg.security_upgradable=$(apt list --upgradable 2>/dev/null | grep -c -- -security)"
  echo "pkg.cache_mtime=$(stat -c %Y /var/cache/apt/pkgcache.bin 2>/dev/null)"
  echo "pkg.auto_updates=$(grep -hs 'Unattended-Upgrade "1"' /etc/apt/apt.conf.d/20auto-upgrades >/dev/null && echo yes || echo no)"
  echo "pkg.count=$(dpkg-query -W 2>/dev/null | wc -l)"
fi
test -f /var/run/reboot-required && echo reboot_required=yes || echo reboot_required=no
echo "uptime_days=$(awk '{print int($1/86400)}' /proc/uptime)"
echo "fw.ufw=$($S ufw status 2>/dev/null | head -1 | awk "{print \$NF}")"
echo "fw.nft_input_policy=$($S nft list chain inet filter input 2>/dev/null | grep -o 'policy [a-z]*' | head -1 | cut -d' ' -f2)"
echo "fw.iptables_input_policy=$($S iptables -S INPUT 2>/dev/null | awk '/^-P INPUT/{print $3}')"
echo "disk.crypt_devices=$(lsblk -rno TYPE 2>/dev/null | grep -c crypt)"
echo "audit.auditd=$(systemctl is-active auditd 2>/dev/null)"
echo "audit.fail2ban=$(systemctl is-active fail2ban 2>/dev/null)"
$S ss -Htlnp 2>/dev/null | awk '{split($6,a,"\""); print "listen="$4" "a[2]}' | sort -u
