<#
  Recon Remediate — upgrade a single package with winget, run under SYSTEM by the
  TacticalRMM agent. Recon passes the package name as the script argument(s).

  Set up in TRMM:
    Settings > Script Manager > New
      Shell:        PowerShell
      Category:     anything (e.g. TRMM(Win):Updates)
      Script Arguments: leave BLANK — Recon supplies the package name at runtime
    Note the script's id and put it in Recon's .env as TRMM_REMEDIATE_SCRIPT_ID.

  Honest caveats — read these:
    * Under SYSTEM, winget is not on PATH; we locate winget.exe in the
      DesktopAppInstaller package folder. On Server SKUs without App Installer,
      winget may simply not exist — the script reports that rather than pretending.
    * winget --name matching is fuzzy. A clean upgrade depends on the installed
      package being known to a winget source under the SAME name. "No applicable
      upgrade" / "no package matched" are NORMAL, non-error outcomes, not proof of
      safety.
    * "The script ran" is NOT "the vulnerability is fixed." Always verify the
      installed version afterwards (re-sync in Recon and check the version moved).
#>

$ErrorActionPreference = 'Stop'

# 1) Package name — rebuild from all args. TRMM drops args onto the command line
#    unquoted, so a multi-word name ("Google Chrome") arrives as separate tokens.
$pkg = ($args -join ' ').Trim()
if ([string]::IsNullOrWhiteSpace($pkg)) {
    Write-Output "ERROR: no package name supplied."
    exit 2
}
Write-Output "Recon Remediate: target package = '$pkg'"

# 2) Locate winget.exe (not on PATH in the SYSTEM context).
$winget = $null
$resolved = Get-Command winget.exe -ErrorAction SilentlyContinue
if ($resolved) {
    $winget = $resolved.Source
}
else {
    $base = Join-Path $env:ProgramFiles 'WindowsApps'
    $dirs = Get-ChildItem -Path $base -Directory -Filter 'Microsoft.DesktopAppInstaller_*8wekyb3d8bbwe' -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending
    foreach ($d in $dirs) {
        $exe = Join-Path $d.FullName 'winget.exe'
        if (Test-Path $exe) { $winget = $exe; break }
    }
}
if (-not $winget) {
    Write-Output "ERROR: winget.exe not found. App Installer may be missing, or this is a Server SKU without winget. Cannot remediate this device via winget."
    exit 3
}
Write-Output "Using winget: $winget"

# 3) Run the upgrade. --silent + accept agreements so it can't block on a prompt.
$wingetArgs = @(
    'upgrade', '--name', $pkg,
    '--silent',
    '--accept-source-agreements',
    '--accept-package-agreements',
    '--disable-interactivity'
)
Write-Output "----- winget upgrade --name `"$pkg`" -----"
try {
    $out  = & $winget @wingetArgs 2>&1 | Out-String
    $code = $LASTEXITCODE
}
catch {
    Write-Output "ERROR running winget: $($_.Exception.Message)"
    exit 4
}
Write-Output $out
Write-Output "winget exit code: $code"

# 4) Interpret the outcome from output text + exit code, rather than trusting a
#    bare exit 0. Classify the common, expected non-fix outcomes explicitly.
if ($out -match 'No installed package found' -or
    $out -match 'No package found matching' -or
    $out -match 'No applicable (update|upgrade) found' -or
    $out -match 'No available upgrade') {
    Write-Output "RESULT: nothing upgraded for '$pkg' — already current, or not matched by a winget source. NOT confirmed patched."
    exit 0
}
if ($out -match 'Successfully installed' -or $code -eq 0) {
    Write-Output "RESULT: winget reported success for '$pkg'. VERIFY the new version in Recon before treating the finding as cleared."
    exit 0
}
Write-Output "RESULT: winget returned $code for '$pkg' — see output above. Not upgraded."
exit $code
