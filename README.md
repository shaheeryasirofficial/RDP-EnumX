<h1 align="center">RDP-Cred-Enum-Toolkit</h1>
<p align="center">
  <strong>Lightweight • Menu-Driven • RDP-Focused Credential & Security Enumeration</strong><br>
  Post-exploitation toolkit optimized for interactive Windows RDP sessions.
</p>

<p align="center">
  <a href="https://github.com/shaheeryasiofficial/rdp-cred-enum-toolkit/stargazers">
    <img src="https://img.shields.io/github/stars/shaheeryasiofficial/rdp-cred-enum-toolkit?style=for-the-badge&logo=github&color=yellow" alt="Stars">
  </a>
  <a href="https://github.com/shaheeryasiofficial/rdp-cred-enum-toolkit/issues">
    <img src="https://img.shields.io/github/issues/shaheeryasiofficial/rdp-cred-enum-toolkit?style=for-the-badge&logo=github&color=red" alt="Issues">
  </a>
  <a href="https://github.com/shaheeryasiofficial/rdp-cred-enum-toolkit/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/shaheeryasiofficial/rdp-cred-enum-toolkit?style=for-the-badge&color=green" alt="License">
  </a>
  <br>
  <img src="https://img.shields.io/badge/PowerShell-5.1+-blue?style=for-the-badge&logo=powershell&logoColor=white" alt="PowerShell">
  <img src="https://img.shields.io/badge/Windows-10%20%7C%2011%20%7C%20Server-important?style=for-the-badge&logo=windows" alt="Windows">
  <img src="https://img.shields.io/badge/Red%20Team-Post%20Exploitation-orange?style=for-the-badge" alt="Red Team">
</p>

<div align="center">
  🔴 Minimal footprint • Living-off-the-land • No binaries • Administrator-friendly
</div>

---

### Core Features

- Clean interactive menu
- AMSI bypass (reflection)
- UAC elevation attempt if not already admin
- Timestamped loot folder on Desktop
- Plain-text + JSON/CSV output easy to read & exfiltrate
- Designed for **RDP sessions** (user or elevated context)

### Enumeration & Detection Modules

| #  | Module                                          | Admin? | Main Output File(s)                        | Value / Purpose                              |
|----|-------------------------------------------------|--------|--------------------------------------------|----------------------------------------------|
| 1  | Windows Credential Manager                      | —      | `credman.json`, `credman.csv`              | Vault + generic creds                        |
| 2  | cmdkey saved network credentials                | No     | `cmdkey.json`                              | RDP, WinRM, share logins                     |
| 3  | Wi-Fi profiles + cleartext passwords            | No     | `wifi.json`                                | Wi-Fi keys                                   |
| 4  | Saved RDP connections & credential blobs        | No     | `rdp_cred_blobs.json`, `rdp_*.reg.txt`     | RDP history & targets                        |
| 5  | Browser saved passwords (Chrome/Edge/Firefox)   | No     | `browser_*.sqlite`, `browser_*.json`       | Login data files                             |
| 6  | LAPS local admin password                       | AD     | `laps.json`                                | ms-Mcs-AdmPwd attribute                      |
| 7  | Unattended / sysprep files                      | No     | `unattended_*`                             | Deployment remnant credentials               |
| 8  | SAM / SYSTEM / SECURITY hives                   | Yes    | `sam.hive`, `system.hive`, `security.hive` | NTLM hashes (offline cracking)               |
| 9  | DPAPI master key locations                      | No     | `dpapi_masterkeys.json`                    | Master keys for credential decryption        |
| 10 | Scheduled Tasks with stored credentials         | No     | `scheduled_tasks_creds.json`               | Tasks running with saved passwords           |
|    |                                                 |        |                                            |                                              |
| 11 | Installed AV / Security Products                | No     | `installed_antivirus.json`                 | Registered AV engines                        |
| 12 | Quick EDR / AV process & service detection      | No     | `edr_av_processes_services.json`           | Common EDR/AV indicators                     |
| 13 | Most common EDR drivers & services              | No     | `edr_drivers.json`                         | Kernel-level EDR drivers                     |
| 14 | Windows Defender status + protections           | No     | `defender_status.json`                     | Real-time, tamper protection, scans          |
| 15 | Security-related running processes              | No     | `security_related_processes.json`          | EDR/AV process list                          |
| C  | Clear common event logs                         | Yes    | —                                          | Security, System, Defender, PowerShell logs  |
| 0  | Exit                                            | —      | —                                          | —                                            |

### Quick Start (RDP)

1. Open PowerShell (preferably as Administrator)
2. Paste the entire script and press Enter
3. Use the menu: type `1`–`15`, `C`, or `0`
