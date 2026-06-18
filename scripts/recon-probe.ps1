<#
  recon-probe.ps1 — Recon capability probe.

  Run under SYSTEM by TRMM (saved as a TRMM script; its id goes in
  TRMM_PROBE_SCRIPT_ID). Takes no arguments. Asks the package managers on THIS
  device what they can actually upgrade, and prints a compact JSON list between
  markers so Recon can record the *fix path* per product:

    RECON_PROBE_BEGIN
    [{"name":..,"current":..,"available":..,"source":"winget"|"choco"}, ...]
    RECON_PROBE_END

  This is intentionally read-only — it upgrades nothing. It just reports what a
  later remediation *could* do, so Recon can set expectations up front instead of
  finding out by a failed upgrade. Note: winget listing a package is not a cast-iron
  guarantee the upgrade will apply (e.g. Adobe-updater-managed apps) — Recon still
  verifies by reading the registry version after any actual remediation.
#>

$ErrorActionPreference = "SilentlyContinue"
$entries = New-Object System.Collections.ArrayList

function Resolve-Winget {
  $w = (Get-Command winget.exe -ErrorAction SilentlyContinue).Source
  if ($w) { return $w }
  # Under SYSTEM the app-execution alias isn't on PATH; resolve the real exe.
  $cand = Get-ChildItem "$env:ProgramFiles\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe\winget.exe" -ErrorAction SilentlyContinue |
          Sort-Object FullName -Descending | Select-Object -First 1
  if ($cand) { return $cand.FullName }
  return $null
}

# ---- winget upgrade (parse the fixed-width table by header column offsets) ----
$wg = Resolve-Winget
if ($wg) {
  $raw = & $wg upgrade --include-unknown --disable-interactivity --accept-source-agreements 2>$null
  $lines = @($raw -split "`r?`n")
  $hi = -1
  for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match '^\s*Name\s+Id\s+Version\s+Available') { $hi = $i; break }
  }
  if ($hi -ge 0) {
    $h = $lines[$hi]
    $cId = $h.IndexOf("Id"); $cVer = $h.IndexOf("Version")
    $cAvail = $h.IndexOf("Available"); $cSrc = $h.IndexOf("Source")
    for ($j = $hi + 2; $j -lt $lines.Count; $j++) {
      $ln = $lines[$j]
      if ($ln -match '^\s*$') { break }
      if ($ln -match '^\s*-+\s*$') { continue }
      if ($ln -match 'upgrades? available' -or $ln -match 'package\(s\) have') { continue }
      if ($cAvail -lt 0 -or $ln.Length -lt $cAvail) { continue }
      $name  = $ln.Substring(0, $cId).Trim()
      $ver   = $ln.Substring($cVer, [Math]::Max(0, $cAvail - $cVer)).Trim()
      if ($cSrc -gt $cAvail -and $ln.Length -ge $cSrc) {
        $avail = $ln.Substring($cAvail, $cSrc - $cAvail).Trim()
      } else {
        $avail = $ln.Substring($cAvail).Trim()
      }
      if ($name -and $avail) {
        [void]$entries.Add([PSCustomObject]@{ name = $name; current = $ver; available = $avail; source = "winget" })
      }
    }
  }
}

# ---- choco outdated (clean machine-readable rows: name|current|available|pinned) ----
$choco = (Get-Command choco.exe -ErrorAction SilentlyContinue).Source
if ($choco) {
  $co = & $choco outdated -r --ignore-pinned 2>$null
  foreach ($line in @($co -split "`r?`n")) {
    if ($line -match '^\s*$') { continue }
    $parts = $line -split '\|'
    if ($parts.Count -ge 3 -and $parts[0] -and $parts[2]) {
      [void]$entries.Add([PSCustomObject]@{ name = $parts[0].Trim(); current = $parts[1].Trim(); available = $parts[2].Trim(); source = "choco" })
    }
  }
}

"RECON_PROBE_BEGIN"
ConvertTo-Json -InputObject @($entries) -Compress -Depth 3
"RECON_PROBE_END"
