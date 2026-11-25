# host profile: Windows (PowerShell). READ-ONLY. ASCII only (remote decodes as legacy codepage).
# Probe: probe.ps1 (per-probe limits; each body is self-contained, it runs in its own runspace).
$ErrorActionPreference = 'SilentlyContinue'
$T = $SpProbeTimeout
Probe sshd $T -Lines {
  $c = Get-Content "$env:ProgramData\ssh\sshd_config"
  $pa = ($c | Where-Object { $_ -match '^\s*PasswordAuthentication' } | Select-Object -Last 1) -replace '^\s*PasswordAuthentication\s+',''
  if (-not $pa) { $pa = 'yes(default)' }
  "sshd.passwordauthentication=$($pa.ToLower())"
  "sshd.permitrootlogin=n/a"
}
Probe os.name $T { $os = Get-CimInstance Win32_OperatingSystem; "$($os.Caption) $($os.Version)" }
Probe uptime_days $T { [int]((Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime).TotalDays }
Probe reboot_required $T { if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {'yes'} else {'no'} }
Probe fw.profile $T -Lines { foreach ($p in Get-NetFirewallProfile) { "fw.profile_$($p.Name.ToLower())=$(if ($p.Enabled) {'on'} else {'off'})" } }
Probe av $T -Lines {
  $mp = Get-MpComputerStatus
  "av.realtime=$(if ($mp.RealTimeProtectionEnabled) {'on'} else {'off'})"
  "av.signature_age_days=$($mp.AntivirusSignatureAge)"
}
Probe disk.bitlocker $T { $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive; if ($bl) { $bl.ProtectionStatus } else { 'unknown' } }
Probe smb.v1 $T { (Get-SmbServerConfiguration).EnableSMB1Protocol }
Probe listen $T -Lines { Get-NetTCPConnection -State Listen | ForEach-Object { "listen=$($_.LocalAddress):$($_.LocalPort) $((Get-Process -Id $_.OwningProcess).ProcessName)" } | Sort-Object -Unique }
Probe pkg.last_hotfix $SpProbeSlowTimeout { $hf = Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1; $hf.InstalledOn.ToString('yyyy-MM-dd') }
