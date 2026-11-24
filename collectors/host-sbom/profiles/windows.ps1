# host-sbom profile: Windows (PowerShell). READ-ONLY. ASCII source only. OS build + update revision, installed
# updates (KB), installed programs (machine + current user uninstall keys).
$ErrorActionPreference = 'SilentlyContinue'
$v = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$os = Get-CimInstance Win32_OperatingSystem
"os.family=windows"
"os.name=$($os.Caption)"
"os.product=$($v.ProductName)"
"os.edition=$($v.EditionID)"
"os.version=$($v.DisplayVersion)"
"os.build=10.0.$($v.CurrentBuild).$($v.UBR)"
"arch=$($env:PROCESSOR_ARCHITECTURE)"
foreach ($h in Get-HotFix) {
  $d = ''
  if ($h.InstalledOn) { $d = $h.InstalledOn.ToString('yyyy-MM-dd') }
  "pkg`twindows-kb`t$($h.HotFixID)`t$d`t$($h.Description)`t`t"
}
$keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
$seen = @{}
foreach ($k in $keys) {
  foreach ($p in Get-ItemProperty $k) {
    if (-not $p.DisplayName -or $p.SystemComponent -eq 1) { continue }
    $n = ($p.DisplayName -replace "[`t`r`n]", ' ').Trim()
    $ver = ("" + $p.DisplayVersion) -replace "[`t`r`n]", ' '
    $id = "$n|$ver"
    if ($seen.ContainsKey($id)) { continue }
    $seen[$id] = 1
    $pub = ("" + $p.Publisher) -replace "[`t`r`n]", ' '
    "pkg`twindows-program`t$n`t$ver`t$pub`t`t"
  }
}
