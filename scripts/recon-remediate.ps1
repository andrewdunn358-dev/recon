# Recon Remediate - upgrade a single package via winget OR Chocolatey, run under
# SYSTEM by the TacticalRMM agent. Recon passes the display name as the argument(s).
#
# TRMM setup:
#   Shell: PowerShell  |  Script Arguments: leave BLANK (Recon supplies it)
#   Put this script's id in Recon .env as TRMM_REMEDIATE_SCRIPT_ID.
#
# It tries winget first (matched by display name), then Chocolatey (matched to an
# installed choco package id), and finally reports the package's CURRENT installed
# version straight from the registry uninstall keys - the same place inventory
# reads - via machine-parseable RECON_* markers so Recon can update the software
# list and clear the finding immediately, without waiting for the next inventory.
#
# Markers Recon parses (one value per line):
#   RECON_STATUS <upgraded|nochange|notfound|error>
#   RECON_MANAGER <winget|choco|none>
#   RECON_NEWVERSION <version or empty>

$ErrorActionPreference = 'Continue'

# 1) Package name - rebuild from all args (TRMM passes them unquoted, so a
#    multi-word name like "Google Chrome" arrives split into separate tokens).
$pkg = ($args -join ' ').Trim()
if ([string]::IsNullOrWhiteSpace($pkg)) {
    Write-Output 'ERROR: no package name supplied.'
    Write-Output 'RECON_STATUS error'
    Write-Output 'RECON_MANAGER none'
    Write-Output 'RECON_NEWVERSION '
    exit 2
}
Write-Output "Recon Remediate: target package = $pkg"

# --- helper: read installed version from the registry uninstall keys ----------
function Get-InstalledVersion([string]$name) {
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $apps = foreach ($k in $keys) { Get-ItemProperty $k -ErrorAction SilentlyContinue }
    $m = $apps | Where-Object { $_.DisplayName -and ($_.DisplayName -like "*$name*") -and $_.DisplayVersion } |
         Sort-Object { [string]$_.DisplayVersion } -Descending | Select-Object -First 1
    if ($m) { return [string]$m.DisplayVersion }
    return ''
}

$before = Get-InstalledVersion $pkg
Write-Output "Installed version before: $before"
$manager = 'none'
$upgraded = $false

# 0) Microsoft Office (Click-to-Run / Microsoft 365) is NOT patchable by winget or
#    choco - it updates through Office's own updater. Detect it and drive that
#    instead. The update runs in the BACKGROUND (async), so we can't confirm the
#    new version synchronously - report 'triggered' and let a later sync confirm.
$c2r = Join-Path ${env:ProgramFiles} 'Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe'
if (($pkg -match '(?i)click.?to.?run|microsoft 365') -and (Test-Path $c2r)) {
    Write-Output 'Microsoft Office Click-to-Run detected - updating via OfficeC2RClient (winget/choco cannot patch Office).'
    try {
        & $c2r /update user updatepromptuser=false forceappshutdown=false displaylevel=false
        $manager = 'office-c2r'
        Write-Output 'Office update TRIGGERED. It downloads and applies in the BACKGROUND (often 10+ minutes, and open Office apps may need to close), so the version will not change right away. It will clear on a later sync once it completes.'
    } catch {
        Write-Output ('ERROR triggering Office update: ' + $_.Exception.Message)
    }
    Start-Sleep -Seconds 2
    $after = Get-InstalledVersion $pkg
    $status = if ($after -and $before -and ($after -ne $before)) { 'upgraded' } else { 'triggered' }
    Write-Output "Installed version after: $after"
    Write-Output "RESULT: manager=$manager status=$status (Office update is asynchronous - verify after it finishes)."
    Write-Output "RECON_STATUS $status"
    Write-Output "RECON_MANAGER $manager"
    Write-Output "RECON_NEWVERSION $after"
    exit 0
}

# 2) Try winget (resolve winget.exe - not on PATH under SYSTEM).
$winget = $null
$resolved = Get-Command winget.exe -ErrorAction SilentlyContinue
if ($resolved) { $winget = $resolved.Source }
else {
    $base = Join-Path $env:ProgramFiles 'WindowsApps'
    $dirs = Get-ChildItem -Path $base -Directory -Filter 'Microsoft.DesktopAppInstaller_*8wekyb3d8bbwe' -ErrorAction SilentlyContinue | Sort-Object Name -Descending
    foreach ($d in $dirs) { $exe = Join-Path $d.FullName 'winget.exe'; if (Test-Path $exe) { $winget = $exe; break } }
}
if ($winget) {
    Write-Output "Using winget: $winget"
    $wargs = @('upgrade', '--name', $pkg, '--source', 'winget', '--silent', '--accept-source-agreements', '--accept-package-agreements', '--disable-interactivity')
    $out = & $winget @wargs 2>&1 | Out-String
    Write-Output $out
    $noMatch = 'No installed package found|No package found matching|No applicable (update|upgrade) found|No available upgrade'
    if (($LASTEXITCODE -eq 0 -or $out -match 'Successfully installed') -and ($out -notmatch $noMatch)) {
        $manager = 'winget'; $upgraded = $true
    } else {
        Write-Output 'winget did not upgrade it (no match or already current) - trying Chocolatey...'
    }
} else {
    Write-Output 'winget.exe not found - trying Chocolatey...'
}

# 3) Chocolatey fallback - match the display name to an installed choco package id.
if (-not $upgraded) {
    $choco = Get-Command choco.exe -ErrorAction SilentlyContinue
    if ($choco) {
        Write-Output "Using choco: $($choco.Source)"
        $listed = @()
        try {
            $raw = & choco list --local-only --limit-output 2>$null
            if ($LASTEXITCODE -ne 0 -or -not $raw) { $raw = & choco list --limit-output 2>$null }
            $listed = $raw | ForEach-Object { ($_ -split '\|')[0] } | Where-Object { $_ }
        } catch { $listed = @() }

        # squash to alphanumeric for fuzzy id matching ("Google Chrome" -> "googlechrome")
        $squash = ($pkg -replace '[^a-zA-Z0-9]', '').ToLower()
        $first  = (($pkg -split '\s+')[0] -replace '[^a-zA-Z0-9]', '').ToLower()
        $id = $listed | Where-Object { $_.ToLower() -eq $squash } | Select-Object -First 1
        if (-not $id) { $id = $listed | Where-Object { $_.ToLower() -replace '[^a-z0-9]','' -eq $squash } | Select-Object -First 1 }
        if (-not $id -and $first.Length -ge 4) { $id = $listed | Where-Object { $_.ToLower() -like "*$first*" } | Select-Object -First 1 }

        if ($id) {
            Write-Output "choco match: $id"
            $cout = & choco upgrade $id -y --no-progress --limit-output 2>&1 | Out-String
            Write-Output $cout
            if ($LASTEXITCODE -eq 0 -and $cout -notmatch 'is not installed|cannot be found|0/1') {
                $manager = 'choco'; $upgraded = $true
            }
        } else {
            Write-Output "No installed Chocolatey package matched '$pkg'."
        }
    } else {
        Write-Output 'Chocolatey (choco.exe) not present on this device.'
    }
}

# 4) Read the version AFTER, straight from the registry (manager-agnostic truth).
Start-Sleep -Seconds 2
$after = Get-InstalledVersion $pkg
Write-Output "Installed version after: $after"

# 5) Honest status + machine-parseable markers for Recon.
$status = 'notfound'
if ($after) {
    if ($before -and ($after -ne $before)) { $status = 'upgraded' }
    else { $status = 'nochange' }
}
if ($upgraded -and $status -eq 'nochange') {
    Write-Output ("WARNING: a package manager reported success but the installed " +
        "version did not change ('" + $before + "'). It likely matched the Microsoft " +
        "Store listing or a different package, not the installed desktop app. NOT patched.")
}
Write-Output "RESULT: manager=$manager status=$status version '$before' -> '$after'. Verify in Recon."
Write-Output "RECON_STATUS $status"
Write-Output "RECON_MANAGER $manager"
Write-Output "RECON_NEWVERSION $after"
exit 0
