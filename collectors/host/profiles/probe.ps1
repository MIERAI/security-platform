# Probe helper, prepended by the collector to the Windows profile. READ-ONLY. ASCII only.
#   Probe KEY SECONDS { body }          prints KEY=<first output object of the body>
#   Probe KEY SECONDS { body } -Lines    prints the body's output lines unchanged (e.g. listen=... lines)
# Each body runs in its own runspace (in-process, no new powershell.exe per probe) and sees none of the caller's
# variables. A body still running after SECONDS is stopped and reported as `KEY=unknown` plus `probe.timeout=KEY`
# instead of a value; the rest of the output is unaffected. $SpProbeTimeout / $SpProbeSlowTimeout come from the
# collector (instance config).
if (-not $SpProbeTimeout) { $SpProbeTimeout = 20 }
if (-not $SpProbeSlowTimeout) { $SpProbeSlowTimeout = 90 }
function Probe([string]$Key, [int]$Seconds, [scriptblock]$Body, [switch]$Lines) {
  $ps = [powershell]::Create()
  [void]$ps.AddScript("`$ErrorActionPreference = 'SilentlyContinue'`n" + $Body.ToString())
  $h = $ps.BeginInvoke()
  if ($h.AsyncWaitHandle.WaitOne($Seconds * 1000)) {
    $out = @($ps.EndInvoke($h))
    $ps.Dispose()
    if ($Lines) { $out | ForEach-Object { "$_" } } else { "$Key=$(if ($out.Count) { $out[0] })" }
  } else {
    [void]$ps.BeginStop($null, $null)   # not awaited: a hung provider call must not hang the script
    "$Key=unknown"
    "probe.timeout=$Key"
  }
}
