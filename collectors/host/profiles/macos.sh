# host profile: macOS. READ-ONLY, no sudo. Output: key=value lines. sp_probe/sp_lines: probe.sh (per-command limits).
# Slow, network-dependent probes (Apple's update servers, Homebrew) run LAST with the slow limit.
T=$SP_PROBE_TIMEOUT
FW=/usr/libexec/ApplicationFirewall/socketfilterfw
sp_probe os.name $T 'echo "macOS $(sw_vers -productVersion) ($(sw_vers -buildVersion))"'
sp_probe disk.filevault $T 'fdesetup status 2>/dev/null | head -1 | grep -q "is On" && echo on || echo off'
sp_probe fw.app_firewall $T '$FW --getglobalstate 2>/dev/null | grep -qi enabled && echo on || echo off'
sp_probe fw.stealth $T '$FW --getstealthmode 2>/dev/null | grep -qi -e "is on" -e enabled && echo on || echo off'
sp_probe sip $T 'csrutil status 2>/dev/null | grep -q enabled && echo on || echo off'
sp_probe gatekeeper $T 'spctl --status 2>/dev/null | grep -q enabled && echo on || echo off'
sp_probe ssh.remote_login $T 'launchctl print system/com.openssh.sshd >/dev/null 2>&1 && echo on || echo off'
sp_probe pkg.auto_install_os $T 'defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates 2>/dev/null || echo unset'
sp_probe pkg.auto_security $T 'defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall 2>/dev/null || echo unset'
sp_probe uptime_days $T 'echo $(( ($(date +%s) - $(sysctl -n kern.boottime | awk -F"[ ,]" "{print \$4}")) / 86400 ))'
sp_lines listen $T 'lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | awk "NR>1{print \"listen=\"\$9\" \"\$1}" | sort -u'
sp_probe pkg.brew_outdated $SP_PROBE_SLOW_TIMEOUT 'brew outdated -q 2>/dev/null | wc -l | tr -d " "'
sp_probe pkg.os_updates_pending $SP_PROBE_SLOW_TIMEOUT 'softwareupdate -l 2>&1 | grep -c "^\* Label"'
