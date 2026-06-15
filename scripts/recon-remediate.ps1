# Recon Remediate - winget upgrade of a single package, run under SYSTEM by the
# TacticalRMM agent. Recon passes the package name as the script argument(s).
#
# TRMM setup:
#   Shell: PowerShell   |   Script Arguments: leave BLANK (Recon supplies it)
#   Put this script's id in Recon .env as TRMM_REMEDIATE_SCRIPT_ID.
#
# Caveats: winget is not on PATH under SYSTEM (resolved below); winget --name
# matching is fuzzy ("no applicable upgrade" is normal, not an error); and a
# success message is NOT proof of a fix - always verify the version afterwards.

$ErrorActionPreference = 'Stop'

# 1) Package name - rebuild from all args (TRMM passes them unquoted, so a
#    multi-word name like "Google Chrome" arrives split into separate tokens).
$pkg = ($args -join ' ').Trim()
if ([string]::IsNullOrWhiteSpace($pkg)) {
    Write-Output 'ERROR: no package name supplied.'
    exit 2
}
Write-Output "Recon Remediate: target package = $pkg"

# 2) Locate winget.exe (not on PATH in the SYSTEM context).
$winget = $null
$resolved = Get-Command winget.exe -ErrorAction SilentlyContinue
if ($resolved) {
    $winget = $resolved.Source
}
else {
    $base = Join-Path $env:ProgramFiles 'WindowsApps'
    $dirs = Get-ChildItem -Path $base -Directory -Filter 'Microsoft.DesktopAppInstaller_*8wekyb3d8bbwe' -ErrorAction SilentlyContinue | Sort-Object Name -Descending
    foreach ($d in $dirs) {
        $exe = Join-Path $d.FullName 'winget.exe'
        if (Test-Path $exe) { $winget = $exe; break }
    }
}
if (-not $winget) {
    Write-Output 'ERROR: winget.exe not found. App Installer missing, or a Server SKU without winget. Cannot remediate via winget.'
    exit 3
}
Write-Output "Using winget: $winget"

# 3) Run the upgrade. --silent + accept agreements so it cannot block on a prompt.
$wingetArgs = @('upgrade', '--name', $pkg, '--silent', '--accept-source-agreements', '--accept-package-agreements', '--disable-interactivity')
Write-Output "Running: winget upgrade --name $pkg"
try {
    $out = & $winget @wingetArgs 2>&1 | Out-String
    $code = $LASTEXITCODE
}
catch {
    Write-Output ('ERROR running winget: ' + $_.Exception.Message)
    exit 4
}
Write-Output $out
Write-Output "winget exit code: $code"

# 4) Interpret the outcome honestly rather than trusting a bare exit 0.
$noMatch = 'No installed package found|No package found matching|No applicable (update|upgrade) found|No available upgrade'
if ($out -match $noMatch) {
    Write-Output "RESULT: nothing upgraded for $pkg - already current, or not matched by a winget source. NOT confirmed patched."
    exit 0
}
if (($code -eq 0) -or ($out -match 'Successfully installed')) {
    Write-Output "RESULT: winget reported success for $pkg. VERIFY the new version in Recon before treating the finding as cleared."
    exit 0
}
Write-Output "RESULT: winget returned $code for $pkg - not upgraded. See output above."
exit $code
