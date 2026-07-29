<h1 align="center">RDP-EnumX</h1>
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
  🔴 Minimal footprint &nbsp;•&nbsp; Living-off-the-land &nbsp;•&nbsp; No binaries &nbsp;•&nbsp; Administrator-friendly
</div>

---

### Core Features

- Clean interactive menu with live admin/user context indicator
- AMSI bypass via concatenated reflection avoids plaintext trigger strings
- Timestamped loot folder under `%TEMP%` lower visibility than Desktop
- JSON output throughout for easy parsing and exfiltration
- Admin-required modules skip gracefully in user context rather than erroring
- Designed for RDP sessions in both user and elevated contexts

---

### Enumeration Modules

| # | Module | Admin? | Output | Purpose |
|---|--------|--------|--------|---------|
| 1 | Windows Credential Manager | — | `credman.json` | Vault and generic credentials |
| 2 | cmdkey stored credentials | No | `cmdkey.json` | RDP, WinRM, share logins |
| 3 | WiFi profiles + cleartext passwords | No | `wifi.json` | WiFi keys across all profiles |
| 4 | RDP saved creds, history, .rdp files | No | `rdp_credential_blobs.json`, `rdp_history.txt` | Connection history and DPAPI blobs |
| 5 | Browser files (Chrome/Edge/Brave/Opera/Firefox) | No | `browser_<name>\*` | Login Data, Cookies, Local State, key4.db |
| 6 | LAPS local admin password | AD | `laps.json` | ms-Mcs-AdmPwd + expiry |
| 7 | Unattended / sysprep files | No | `unattended_*` | Deployment credential remnants |
| 8 | SAM / SYSTEM / SECURITY hives | Yes | `*.hive` | Offline NTLM hash extraction |
| 9 | DPAPI master key locations | No | `dpapi_masterkeys.json` | Master key paths for offline decryption |
| 10 | Scheduled tasks with stored credentials | No | `scheduled_tasks.json` | Tasks running under non-default accounts |
| 11 | Services under non-default accounts | No | `services_custom_accounts.json` | Domain/custom service account exposure |

---

### Recon Modules

| # | Module | Admin? | Output | Purpose |
|---|--------|--------|--------|---------|
| 12 | Security posture | No | `security_posture.json` | AV, EDR processes/services/drivers, Defender config, ASR rules plus live console summary |
| 13 | Accessibility key backdoors | No | `accessibility_backdoors.json` | IFEO debugger entries on sethc, utilman, osk, narrator |

---

### What Changed from v1

- **Removed log clearing** clearing Security/System/Defender logs is a high-confidence SIEM alert and draws more attention than it removes
- **Removed UAC elevation popup** spawning a hidden elevated PowerShell process is immediately visible and creates an elevation event log entry
- **Fixed EDR detection logic** original compared process path against a pattern object instead of its string value, producing no results
- **Fixed DPAPI regex** master key filenames are 36-char GUIDs with hyphens, not 40-char hex strings
- **Expanded browser collection** now grabs `Local State` (AES encryption key), `Cookies`, and `Web Data` across Chrome, Edge, Brave, Opera, and all Firefox profiles
- **Output moved to `%TEMP%`** Desktop loot folder is visible to any user on the session; Temp is lower profile
- **AMSI bypass hardened** split across string concatenation to avoid the bypass itself being caught by AMSI on load
- **Added module 11** services running under domain or custom accounts are a common path to credential reuse
- **Added module 13** IFEO accessibility backdoors are a persistence indicator worth checking on any machine you land on

---

### Quick Start

```powershell
# Run in any PowerShell session on the RDP target
# Paste full script content and press Enter
# Or load from file:
powershell -ep bypass -f recon_toolkit.ps1
```

Menu accepts `1`–`13` or `0` to exit. Each module reports status inline and writes output to the timestamped folder shown in the menu header.
