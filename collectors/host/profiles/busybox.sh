# host profile: busybox/OpenWrt-like embedded devices (routers). READ-ONLY. sp_probe/sp_lines: probe.sh.
T=$SP_PROBE_TIMEOUT
D=$(ps w 2>/dev/null | grep '[d]ropbear' | head -1)
case "$D" in *" -s"*) echo "sshd.passwordauthentication=no";; *) echo "sshd.passwordauthentication=yes";; esac
case "$D" in *" -g"*) echo "sshd.permitrootlogin=without-password";; *) echo "sshd.permitrootlogin=yes";; esac
if [ -f /usr/share/xiaoqiang/xiaoqiang_version ]; then
  echo "os.name=xiaoqiang ROM $(awk -F"'" '/option ROM/{print $2}' /usr/share/xiaoqiang/xiaoqiang_version) $(awk -F"'" '/option HARDWARE/{print $2}' /usr/share/xiaoqiang/xiaoqiang_version)"
else echo "os.name=$(. /etc/openwrt_release 2>/dev/null; echo $DISTRIB_DESCRIPTION)"; fi
echo "os.kernel=$(uname -r)"
echo "telnetd=$(ps w | grep -c '[t]elnetd')"
echo "uptime_days=$(awk '{print int($1/86400)}' /proc/uptime)"
sp_probe fw.iptables_input_policy $T 'iptables -S INPUT 2>/dev/null | awk "/^-P INPUT/{print \$3}"'
sp_lines listen $T 'netstat -tln 2>/dev/null | awk "NR>2{print \"listen=\"\$4}" | sort -u'
