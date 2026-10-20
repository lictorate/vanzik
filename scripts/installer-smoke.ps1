# installer-smoke.ps1 — install (and uninstall) Vanzik on Windows the way
# a user does, then check what the installer left behind. Run by
# .github/workflows/installer-smoke.yml under Windows PowerShell 5.1 and 7.
#
#   -Mode published  the public one-liner: irm .../releases/latest/download/install.ps1 | iex
#   -Mode local      this checkout's scripts/install.ps1, installing -Want
#   -Engine          which PowerShell runs the installer: powershell (5.1) or pwsh
#
# The installer adds its folder to the user PATH. With VANZIK_NO_MODIFY_PATH=1
# already set, the check flips to "PATH left alone" — for runs on a real machine.
param(
    [ValidateSet('published', 'local')] [string] $Mode = 'published',
    [Parameter(Mandatory = $true)] [string] $Want,
    [ValidateSet('powershell', 'pwsh')] [string] $Engine = 'powershell'
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$Repo = 'lictorate/vanzik'
$Url = "https://github.com/$Repo/releases/latest/download/install.ps1"
$Want = $Want -replace '^v', ''
$WantRe = [regex]::Escape($Want)
$env:VANZIK_NO_UPDATE_CHECK = '1'

function Pass([string] $Message) { Write-Host "PASS  $Message" }
function Fail([string] $Message) { Write-Host "FAIL  $Message"; exit 1 }

# Runs the installer under test in a fresh $Engine process, as a user would:
# the one-liner, or this checkout's script through the same `iex` path.
function Install-Vanzik {
    $ErrorActionPreference = 'Continue'  # a failing install writes to stderr
    if ($Mode -eq 'published') {
        $cmd = "irm $Url | iex"
    } else {
        $env:VANZIK_VERSION = $Want
        $cmd = "iex (Get-Content -Raw '$PSScriptRoot\install.ps1')"
    }
    $out = & $Engine -NoProfile -ExecutionPolicy Bypass -Command $cmd 2>&1 | Out-String
    $code = $LASTEXITCODE
    Remove-Item Env:VANZIK_VERSION -ErrorAction SilentlyContinue
    return @{ Out = $out; Code = $code }
}

# Uninstall and the updated/downgraded/reinstalled messages arrived after the
# v1.2.0 installer; they are checked only when the installer under test has
# them (this checkout's always does; a published one from v1.2.0 does not).
# GitHub serves release assets as application/octet-stream, for which
# Invoke-WebRequest's .Content is a byte[]: -match on it never matched, so the
# published-mode run skipped every check gated on $newer (found on v1.3.0).
$source = if ($Mode -eq 'published') {
    $content = (Invoke-WebRequest -UseBasicParsing $Url).Content
    if ($content -is [byte[]]) { [Text.Encoding]::UTF8.GetString($content) } else { $content }
} else {
    Get-Content -Raw "$PSScriptRoot\install.ps1"
}
$newer = $source -match 'VANZIK_UNINSTALL'

# Runs the installer under test in uninstall mode, the way the docs say to.
function Uninstall-Vanzik([switch] $Purge) {
    $env:VANZIK_UNINSTALL = '1'
    if ($Purge) { $env:VANZIK_PURGE = '1' }
    $r = Install-Vanzik
    Remove-Item Env:VANZIK_UNINSTALL, Env:VANZIK_PURGE -ErrorAction SilentlyContinue
    return $r
}

# A stand-in vanzik.exe whose --version prints the given release, built
# with the C# compiler Windows PowerShell 5.1 ships, so no Go is needed.
function New-VersionStub([string] $Folder, [string] $Version) {
    $exe = Join-Path $Folder 'vanzik.exe'
    Remove-Item $exe -Force -ErrorAction SilentlyContinue
    $class = 'Stub' + ($Version -replace '\D', '')
    $src = "public static class $class { public static void Main() { System.Console.WriteLine(""vanzik $Version""); } }"
    Add-Type -TypeDefinition $src -OutputAssembly $exe -OutputType ConsoleApplication
}

$arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'amd64' }
Write-Host "== $Mode installer via $Engine, windows/$arch, expecting $Want"

# 1. Fresh install.
$r = Install-Vanzik
$r.Out.Trim() -split "`n" | ForEach-Object { Write-Host "    | $($_.TrimEnd())" }
if ($r.Code -ne 0) { Fail "installer exited $($r.Code)" }
if ($r.Out -match 'Checksum verified') { Pass 'checksum verified' } else { Fail "no 'Checksum verified' line" }
if ($r.Out -cmatch "(?m)^\s*Installed Vanzik $WantRe") { Pass "installed $Want" } else { Fail "no 'Installed Vanzik $Want'" }

# 2. All three binaries, runnable, at the expected version.
$dir = if ($env:VANZIK_INSTALL_DIR) { $env:VANZIK_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\Vanzik\bin' }
foreach ($t in 'vanzik', 'vanzik-mcp-gateway', 'vanzik-llm-proxy') {
    if (Test-Path (Join-Path $dir "$t.exe")) { Pass "$t.exe installed" } else { Fail "missing $dir\$t.exe" }
}
$v = (& (Join-Path $dir 'vanzik.exe') --version 2>&1 | Out-String).Trim()
if ($v -match $WantRe) { Pass "vanzik --version -> $v" } else { Fail "version was: $v" }

# 3. PATH: added by default, left alone when the operator opted out.
$onPath = ([Environment]::GetEnvironmentVariable('Path', 'User') -split ';') -contains $dir
if ($env:VANZIK_NO_MODIFY_PATH -eq '1') {
    if (-not $onPath) { Pass 'VANZIK_NO_MODIFY_PATH=1 left the user PATH alone' } else { Fail 'user PATH changed despite VANZIK_NO_MODIFY_PATH=1' }
} else {
    if ($onPath) { Pass 'install folder added to the user PATH' } else { Fail 'install folder not on the user PATH' }
}

# 4. The starter policy exists and validates.
$policy = Join-Path $env:APPDATA 'vanzik\default.yaml'
if (Test-Path $policy) { Pass "starter policy at $policy" } else { Fail 'no starter policy' }
& (Join-Path $dir 'vanzik.exe') validate --policy $policy *> $null
if ($LASTEXITCODE -eq 0) { Pass 'starter policy validates' } else { Fail 'starter policy failed validate' }

# 5. Running it again reinstalls cleanly and keeps the operator's policy.
Add-Content -Path $policy -Value '# operator edit'
$r2 = Install-Vanzik
$againLine = if ($newer) { "Reinstalled Vanzik $Want" } else { "Installed Vanzik $Want" }
if ($r2.Code -eq 0 -and $r2.Out -cmatch "(?m)^\s*$([regex]::Escape($againLine))") { Pass "rerun: $againLine" } else { Write-Host $r2.Out; Fail "expected '$againLine' on rerun" }
if ((Get-Content $policy -Tail 1) -eq '# operator edit') { Pass 'rerun kept the existing policy' } else { Fail 'rerun overwrote the policy' }

# 6. A tampered archive is refused and nothing is installed. The mirror is
#    served over HTTP: PowerShell 7's Invoke-WebRequest rejects file:// URLs.
$tmp = [IO.Path]::GetTempPath()
$mirror = Join-Path $tmp ('ag-mirror-' + [Guid]::NewGuid().ToString('N'))
$target = Join-Path $tmp ('ag-target-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $mirror | Out-Null
$archive = "vanzik_${Want}_windows_$arch.zip"
$base = if ($env:VANZIK_DOWNLOAD_URL) { $env:VANZIK_DOWNLOAD_URL.TrimEnd('/') } else { "https://github.com/$Repo/releases/download/v$Want" }
Invoke-WebRequest -UseBasicParsing "$base/$archive" -OutFile (Join-Path $mirror $archive)
Invoke-WebRequest -UseBasicParsing "$base/checksums.txt" -OutFile (Join-Path $mirror 'checksums.txt')
[IO.File]::AppendAllText((Join-Path $mirror $archive), 'tampered')

$port = Get-Random -Minimum 20000 -Maximum 40000
$server = Start-Process -FilePath python -ArgumentList '-m', 'http.server', $port, '--bind', '127.0.0.1', '--directory', $mirror -PassThru -WindowStyle Hidden
try {
    for ($i = 0; $i -lt 50; $i++) {
        try { Invoke-WebRequest -UseBasicParsing "http://127.0.0.1:$port/checksums.txt" | Out-Null; break } catch { Start-Sleep -Milliseconds 200 }
    }
    $saved = @{ Url = $env:VANZIK_DOWNLOAD_URL; Dir = $env:VANZIK_INSTALL_DIR; Path = $env:VANZIK_NO_MODIFY_PATH }
    $env:VANZIK_DOWNLOAD_URL = "http://127.0.0.1:$port"
    $env:VANZIK_INSTALL_DIR = $target
    $env:VANZIK_NO_MODIFY_PATH = '1'
    $t = Install-Vanzik
    $env:VANZIK_DOWNLOAD_URL = $saved.Url; $env:VANZIK_INSTALL_DIR = $saved.Dir; $env:VANZIK_NO_MODIFY_PATH = $saved.Path
} finally {
    Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
}
if ($t.Code -ne 0 -and $t.Out -match 'checksum mismatch') { Pass 'tampered archive refused (checksum mismatch)' } else { Write-Host $t.Out; Fail 'tampered archive was not refused for its checksum' }
if (-not (Test-Path (Join-Path $target 'vanzik.exe'))) { Pass 'nothing installed from the tampered archive' } else { Fail 'a binary was installed' }

# 7. The installer says whether it updated, downgraded (with a warning) or
#    reinstalled, judged by the version the binary already there reports.
if ($newer) {
    $stub = Join-Path $tmp ('ag-stub-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $stub | Out-Null
    $saved = @{ Dir = $env:VANZIK_INSTALL_DIR; Path = $env:VANZIK_NO_MODIFY_PATH }
    $env:VANZIK_INSTALL_DIR = $stub
    $env:VANZIK_NO_MODIFY_PATH = '1'

    New-VersionStub $stub '9.9.9'
    $s = Install-Vanzik
    if ($s.Code -eq 0 -and $s.Out -match "Downgraded Vanzik 9\.9\.9 -> $WantRe") { Pass "over 9.9.9: Downgraded 9.9.9 -> $Want" } else { Write-Host $s.Out; Fail 'no Downgraded line' }
    if ($s.Out -match "Warning: $WantRe is older than the 9\.9\.9 you had") { Pass 'downgrade warns' } else { Write-Host $s.Out; Fail 'no downgrade warning' }

    New-VersionStub $stub '0.1.0'
    $s = Install-Vanzik
    if ($s.Code -eq 0 -and $s.Out -match "Updated Vanzik 0\.1\.0 -> $WantRe") { Pass "over 0.1.0: Updated 0.1.0 -> $Want" } else { Write-Host $s.Out; Fail 'no Updated line' }
    if ($s.Out -match 'Warning:') { Write-Host $s.Out; Fail 'an update must not warn' }

    $env:VANZIK_INSTALL_DIR = $saved.Dir; $env:VANZIK_NO_MODIFY_PATH = $saved.Path
}

# 8. Uninstall removes the binaries (and on Windows the PATH entry) and keeps
#    the policy, saying where; a second run finds nothing and still succeeds;
#    VANZIK_PURGE=1 also deletes the policy folder; purge on its own is
#    refused.
if ($newer) {
    $confdir = Join-Path $env:APPDATA 'vanzik'
    $u = Uninstall-Vanzik
    $u.Out.Trim() -split "`n" | ForEach-Object { Write-Host "    | $($_.TrimEnd())" }
    if ($u.Code -ne 0) { Fail "uninstall exited $($u.Code)" }
    foreach ($t in 'vanzik', 'vanzik-mcp-gateway', 'vanzik-llm-proxy') {
        if (-not (Test-Path (Join-Path $dir "$t.exe"))) { Pass "uninstall removed $t.exe" } else { Fail "uninstall left $dir\$t.exe" }
    }
    $onPath = ([Environment]::GetEnvironmentVariable('Path', 'User') -split ';') -contains $dir
    if ($env:VANZIK_NO_MODIFY_PATH -eq '1') {
        if (-not $onPath) { Pass 'user PATH still untouched (VANZIK_NO_MODIFY_PATH=1)' } else { Fail 'user PATH gained the folder' }
    } else {
        if (-not $onPath) { Pass 'uninstall took the folder off the user PATH' } else { Fail 'install folder still on the user PATH' }
    }
    if ((Test-Path $policy) -and $u.Out -match [regex]::Escape("Kept your policy folder $confdir")) { Pass 'uninstall kept the policy and said where' } else { Fail 'uninstall did not keep or name the policy folder' }

    $u2 = Uninstall-Vanzik
    if ($u2.Code -eq 0 -and $u2.Out -match 'not installed in') { Pass 'second uninstall: nothing to remove, exit 0' } else { Write-Host $u2.Out; Fail 'second uninstall output' }

    $null = Install-Vanzik
    $p = Uninstall-Vanzik -Purge
    if ($p.Code -eq 0 -and -not (Test-Path (Join-Path $dir 'vanzik.exe')) -and -not (Test-Path $confdir)) { Pass "purge removed the binaries and $confdir" } else { Write-Host $p.Out; Fail 'purge left files behind' }

    $env:VANZIK_PURGE = '1'
    $m = Install-Vanzik
    Remove-Item Env:VANZIK_PURGE -ErrorAction SilentlyContinue
    # pwsh 7 renders the refusal as a coloured error wrapped to the console
    # width, which can split the phrase across lines; match it unwrapped.
    $plain = ($m.Out -replace "\e\[[0-9;]*m", '') -replace '\s+', ' '
    if ($m.Code -ne 0 -and $plain -match 'only applies together with VANZIK_UNINSTALL') { Pass 'purge on its own is refused' } else { Write-Host $m.Out; Fail 'purge on its own was not refused' }
}

# 9. Over an AgentGuard 1.x install (this project's name before 2.0), the
#    installer moves it to Vanzik: %APPDATA%\agentguard and
#    %LOCALAPPDATA%\AgentGuard\data byte for byte, the database renamed,
#    setup.json's paths, and the coding agents' hooks pointed at vanzik.exe
#    with the old files kept as .vanzik-backup. Everything it touches is in
#    a profile folder of its own.
if ($source -match 'migrate --from-agentguard') {
    $home9 = Join-Path $tmp ('ag-home-' + [Guid]::NewGuid().ToString('N'))
    $roaming = Join-Path $home9 'Roaming'
    $local = Join-Path $home9 'Local'
    $oldCfg = Join-Path $roaming 'agentguard'
    $oldData = Join-Path $local 'AgentGuard\data'
    $claudeDir = Join-Path $home9 '.claude'
    $bin9 = Join-Path $local 'Programs\Vanzik\bin'
    foreach ($d in $oldCfg, $oldData, $claudeDir) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    $write = { param($Path, $Text) [IO.File]::WriteAllText($Path, $Text) }  # UTF-8, no BOM
    & $write (Join-Path $oldCfg 'default.yaml') "version: `"1`"`nname: operator policy`n"
    & $write (Join-Path $oldCfg 'api-key') "k3y`n"
    & $write (Join-Path $oldCfg 'setup.json') (@{ port = 8080; policy = (Join-Path $oldCfg 'default.yaml'); data_dir = $oldData; api_key = $true; login_start = $false } | ConvertTo-Json)
    & $write (Join-Path $oldData 'agentguard.db') 'db'
    & $write (Join-Path $oldData 'audit.jsonl') "{`"seq`":1}`n"
    # Claude Code's hook as AgentGuard 1.x's setup wrote it, failing closed,
    # next to a hook of the user's own.
    $oldHook = '"C:/Users/u/AppData/Local/Programs/AgentGuard/bin/agentguard.exe" hook claude-code --fail-closed'
    $settings = @{ hooks = @{ PreToolUse = @(
                @{ matcher = 'Bash'; hooks = @(@{ type = 'command'; command = './mine.cmd' }) },
                @{ matcher = 'Bash'; hooks = @(@{ type = 'command'; command = $oldHook; timeout = 330 }) }) } } | ConvertTo-Json -Depth 10
    $claudeSettings = Join-Path $claudeDir 'settings.json'
    & $write $claudeSettings $settings

    $saved = @{}
    $sandbox = @{ USERPROFILE = $home9; APPDATA = $roaming; LOCALAPPDATA = $local; VANZIK_INSTALL_DIR = $bin9; VANZIK_NO_MODIFY_PATH = '1'
        CLAUDE_CONFIG_DIR = $null; CURSOR_CONFIG_DIR = $null; GEMINI_CLI_HOME = $null; CODEX_HOME = $null }
    foreach ($k in $sandbox.Keys) { $saved[$k] = [Environment]::GetEnvironmentVariable($k); [Environment]::SetEnvironmentVariable($k, $sandbox[$k]) }
    try {
        $r9 = Install-Vanzik
        $again = (& (Join-Path $bin9 'vanzik.exe') migrate --from-agentguard 2>&1 | Out-String)
    } finally {
        foreach ($k in $saved.Keys) { [Environment]::SetEnvironmentVariable($k, $saved[$k]) }
    }
    $r9.Out.Trim() -split "`n" | ForEach-Object { Write-Host "    | $($_.TrimEnd())" }
    if ($r9.Code -ne 0) { Fail "install over an AgentGuard 1.x setup exited $($r9.Code)" }

    $newCfg = Join-Path $roaming 'vanzik'
    $newData = Join-Path $local 'Vanzik\data'
    if ((Get-Content -Raw (Join-Path $newCfg 'api-key')) -eq "k3y`n") { Pass "API key moved to $newCfg" } else { Fail 'API key not moved' }
    if ((Get-Content -Raw (Join-Path $newCfg 'default.yaml')) -match 'operator policy') { Pass "the operator's policy moved, not the starter one" } else { Fail 'policy not moved' }
    $st = Get-Content -Raw (Join-Path $newCfg 'setup.json') | ConvertFrom-Json
    if ($st.policy -eq (Join-Path $newCfg 'default.yaml') -and $st.data_dir -eq $newData) { Pass 'setup.json points into the new folders' } else { Fail "setup.json: policy=$($st.policy) data_dir=$($st.data_dir)" }
    if ((Test-Path (Join-Path $newData 'vanzik.db')) -and -not (Test-Path (Join-Path $local 'AgentGuard'))) { Pass 'database renamed to vanzik.db; %LOCALAPPDATA%\AgentGuard removed' } else { Fail 'database or data folder not moved' }
    if ((Get-Content -Raw (Join-Path $newData 'audit.jsonl')) -eq "{`"seq`":1}`n") { Pass 'audit log moved unchanged' } else { Fail 'audit log changed' }
    if ((Get-Item $oldCfg -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { Pass "$oldCfg links to the new folder" } else { Fail "no link left at $oldCfg" }
    $cmds = @((Get-Content -Raw $claudeSettings | ConvertFrom-Json).hooks.PreToolUse | ForEach-Object { $_.hooks } | ForEach-Object { $_.command })
    # By its end: the runner's temp folder may be an 8.3 short name, which
    # vanzik resolves to the long one.
    $want = '*/Programs/Vanzik/bin/vanzik.exe" hook claude-code --fail-closed'
    if (@($cmds | Where-Object { $_ -like $want }).Count -eq 1 -and $cmds -contains './mine.cmd') { Pass "Claude Code's hook runs vanzik.exe, still failing closed, beside the user's own" } else { Write-Host ($cmds -join "`n"); Fail "Claude Code's hook not rewritten (want $want)" }
    if ((Get-Content -Raw "$claudeSettings.vanzik-backup") -eq $settings) { Pass 'the old settings are kept as .vanzik-backup' } else { Fail 'no backup of the old settings' }
    if ($again -match 'nothing to migrate') { Pass 'a second migration finds nothing to do' } else { Write-Host $again; Fail 'second migration did something' }
    Remove-Item $home9 -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host 'ALL PASS'
# Explicit: $LASTEXITCODE still holds the tampered install's deliberate
# failure, and the Actions PowerShell wrapper exits with $LASTEXITCODE.
exit 0
