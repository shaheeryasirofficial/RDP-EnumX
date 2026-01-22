<h1 align="center">RDP-Cred-Enum-Toolkit</h1>

<p align="center">
  <strong>Lightweight • Menu-Driven • RDP-Optimized Credential Enumeration</strong><br>
  Post-exploitation credential harvesting toolkit for Windows systems accessed via RDP.
</p>

<p align="center">
  <a href="https://github.com/shaheeryasiofficial/rdp-cred-enum-toolkit/stargazers">
    <img src="https://img.shields.io/github/stars/shaheeryasiofficial/rdp-cred-enum-toolkit?style=for-the-badge&logo=github&color=yellow" alt="GitHub stars">
  </a>
  <a href="https://github.com/shaheeryasiofficial/rdp-cred-enum-toolkit/issues">
    <img src="https://img.shields.io/github/issues/shaheeryasiofficial/rdp-cred-enum-toolkit?style=for-the-badge&logo=github&color=red" alt="GitHub issues">
  </a>
  <a href="https://github.com/shaheeryasiofficial/rdp-cred-enum-toolkit/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/shaheeryasiofficial/rdp-cred-enum-toolkit?style=for-the-badge&logo=opensourceinitiative&color=green" alt="License">
  </a>
  <br>
  <img src="https://img.shields.io/badge/PowerShell-5.1+-blue?style=for-the-badge&logo=powershell&logoColor=white" alt="PowerShell">
  <img src="https://img.shields.io/badge/Windows-10%20%7C%2011%20%7C%20Server-important?style=for-the-badge&logo=windows&logoColor=white" alt="Windows">
  <img src="https://img.shields.io/badge/Red%20Team-Post%20Exploitation-orange?style=for-the-badge" alt="Red Team">
</p>

<div align="center">
  <br>
  🔴 Lightweight • Living-off-the-land • Minimal footprint • Menu-driven
  <br><br>
</div>

---

### ✨ Features

- Interactive menu – run single modules or everything at once (`A`)
- Basic AMSI bypass via reflection (included at the top)
- Privilege escalation attempt (UAC fallback when not elevated)
- **Plain text output by default** – easy to read & exfiltrate immediately
- Optional XOR + Base64 encoding (key 0x42 → `.xor64`) via menu option `E`
- No binaries dropped – uses only native Windows commands & PowerShell
- Designed for interactive RDP sessions (user or elevated context)
- Timestamped loot folder created on Desktop

### 🛠️ Enumeration Modules

| #  | Module                                      | Admin?       | Main Output File(s)                          | Purpose / Typical Value                   |
|----|---------------------------------------------|--------------|----------------------------------------------|-------------------------------------------|
| 1  | Windows Credential Manager                  | Sometimes    | `credman_all.csv`                            | Vault, generic, domain, web creds         |
| 2  | cmdkey stored credentials                   | No           | `cmdkey_list.txt`                            | Network shares, RDP, WinRM saved logins   |
| 3  | Wi-Fi profiles & passwords                  | No           | `wifi_passwords.csv`                         | Cleartext Wi-Fi keys                      |
| 4  | Saved RDP connections & credential blobs    | No           | `cred_blobs.csv`, `rdp_servers.reg.txt`      | RDP history & targets                     |
| 5  | Browser saved passwords                     | No           | `Chrome_creds.sqlite`, `Edge_creds.sqlite`, `Firefox_creds.json` | Chrome / Edge / Firefox login data |
| 6  | LAPS local admin passwords                  | AD rights    | `laps.txt`                                   | ms-Mcs-AdmPwd attribute                   |
| 7  | IE / legacy Edge IntelliForms               | No           | `ie_intelliforms.reg.txt`                    | Legacy saved form data                    |
| 8  | Unattended / sysprep / setup files          | No           | `unattend_*.xml`, `unattend_*.txt`           | Plaintext creds from deployment remnants  |
| 9  | Recent files, RunMRU, PowerShell history    | No           | `recent.csv`, `runmru.txt`, `ps_history.txt` | User activity & command traces            |
| 10 | SAM / SYSTEM / SECURITY hives               | Yes + priv   | `SAM`, `SYSTEM`, `SECURITY`                  | NTLM hashes (offline cracking)            |
| A  | Run **ALL** modules                         | Varies       | All files above                              | Complete credential sweep                 |
| E  | Encode all loot (XOR+Base64)                | —            | All files → `.xor64` (originals deleted)     | Optional obfuscation before exfil         |
| 0  | Exit                                        | —            | —                                            | —                                         |

### 🚀 Quick Start

**Method 1 – Paste & Execute** (recommended in most RDP scenarios)

1. Open PowerShell in the RDP session (preferably as administrator)
2. Copy the **entire script** from [`rdp-cred-enum-toolkit.ps1`](rdp-cred-enum-toolkit.ps1)
3. Paste it into the PowerShell console and press Enter
4. Use the menu: type a number (1–10), `A` (all), or `E` (encode loot)

**Method 2 – Encoded one-liner** (better for evasion / memory-only execution)

Generate the Base64-encoded version of the full script first (on your machine):

```powershell
# Run locally (not on target)
$scriptContent = Get-Content -Path .\rdp-cred-enum-toolkit.ps1 -Raw -Encoding UTF8
$bytes = [System.Text.Encoding]::Unicode.GetBytes($scriptContent)
$encoded = [Convert]::ToBase64String($bytes)
Set-Clipboard -Value $encoded   # or $encoded | Set-Content encoded.txt
