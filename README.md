# DislinxExec

### Windows Discovery & Asset Assessment Engine

![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=for-the-badge\&logo=windows)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?style=for-the-badge\&logo=powershell)
![Security Research](https://img.shields.io/badge/Security-Research-red?style=for-the-badge)
![License](https://img.shields.io/badge/License-Lab%20Use-555555?style=for-the-badge)

---

## What is DislinxExec?

DislinxExec adalah single-file PowerShell tool untuk melakukan discovery dan asset assessment pada Windows.

Tool ini dibuat untuk membantu pentester, security researcher, dan CTF player mengumpulkan informasi dari Windows host dan environment di sekitarnya, kemudian mengidentifikasi asset yang menarik untuk diperiksa lebih lanjut.

DislinxExec menggabungkan beberapa proses discovery dalam satu workflow:

* Windows system enumeration
* User and group discovery
* Process discovery
* Service discovery
* Scheduled task discovery
* Installed software discovery
* Network configuration
* Active connection discovery
* SMB share discovery
* Firewall configuration
* Application and service detection
* Nmap-based network discovery
* Interesting asset detection
* Asset interest scoring
* MITRE ATT&CK mapping
* JSON, CSV, dan HTML reporting

---

## Purpose

Dalam penetration testing atau CTF, discovery merupakan salah satu tahap penting sebelum melakukan assessment lebih lanjut.

Setelah mendapatkan akses ke sebuah Windows host, tester biasanya perlu mengetahui:

```text
Operating System
Users
Groups
Processes
Services
Applications
Network Configuration
Open Connections
Shares
Scheduled Tasks
Development Environment
Application Directories
Configuration Files
Backup Files
Database Files
```

DislinxExec mengotomatisasi proses pengumpulan informasi tersebut sehingga tester tidak perlu melakukan enumeration secara manual satu per satu.

Tool ini bukan vulnerability scanner.

Fokus utamanya adalah:

```text
DISCOVERY
    |
    v
ASSET IDENTIFICATION
    |
    v
ASSET CORRELATION
    |
    v
INTEREST SCORING
    |
    v
MANUAL ASSESSMENT
```

---

## How It Works

```text
                     DislinxExec
                          |
             +------------+------------+
             |                         |
       Windows Host              Network Target
             |                         |
     +-------+-------+         +-------+-------+
     |       |       |         |       |       |
   System  Process Service    Nmap    SMB    HTTP
     |       |       |         |       |       |
     +-------+-------+---------+-------+-------+
                          |
                          v
                  Asset Correlation
                          |
                          v
                   Interest Scoring
                          |
                          v
                    Report Engine
                          |
             +------------+------------+
             |            |            |
            JSON         CSV          HTML
```

---

## Core Capabilities

### Windows Discovery

Mengumpulkan informasi mengenai Windows host:

```text
Hostname
Domain
Operating System
OS Version
Build Number
Architecture
Manufacturer
Model
RAM
Last Boot Time
```

MITRE ATT&CK:

```text
T1082 - System Information Discovery
```

---

### User and Group Discovery

Mengidentifikasi akun dan group yang tersedia:

```text
Username
Domain
SID
Disabled Status
Lockout Status
Local Account
Group Membership
```

MITRE ATT&CK:

```text
T1033 - System Owner/User Discovery
T1069 - Permission Groups Discovery
```

---

### Process Discovery

Mengumpulkan proses yang sedang berjalan:

```text
Process ID
Parent Process ID
Process Name
Executable Path
Command Line
```

MITRE ATT&CK:

```text
T1057 - Process Discovery
```

---

### Service Discovery

Mendeteksi Windows services:

```text
Service Name
Display Name
State
Start Mode
Start Account
Executable Path
```

DislinxExec juga menandai service yang executable-nya berada pada lokasi yang tidak biasa untuk pemeriksaan manual.

MITRE ATT&CK:

```text
T1007 - System Service Discovery
```

---

### Scheduled Task Discovery

Menginventarisasi scheduled tasks:

```text
Task Name
Task Path
State
```

MITRE ATT&CK:

```text
T1053 - Scheduled Task/Job
```

---

### Network Discovery

Mengumpulkan:

```text
Network Interface
IPv4
IPv6
Gateway
DNS
Active TCP Connections
Local Ports
Remote Addresses
Remote Ports
Connection State
```

MITRE ATT&CK:

```text
T1016 - System Network Configuration Discovery
T1049 - System Network Connections Discovery
```

---

### Software Discovery

Mengidentifikasi software yang terinstall melalui Windows registry:

```text
Application Name
Version
Publisher
Install Date
Install Location
```

MITRE ATT&CK:

```text
T1518 - Software Discovery
```

---

### SMB Share Discovery

Mengidentifikasi SMB shares pada host lokal:

```text
Share Name
Path
Description
Scope
```

MITRE ATT&CK:

```text
T1135 - Network Share Discovery
```

---

## Nmap Integration

Jika Nmap tersedia, DislinxExec dapat menggunakannya sebagai network discovery engine.

Profile yang tersedia:

```text
Quick
Standard
Deep
```

Quick:

```powershell
.\DislinxExec.ps1 -Target 192.168.56.101 -Profile Quick
```

Standard:

```powershell
.\DislinxExec.ps1 -Target 192.168.56.101 -Profile Standard
```

Deep:

```powershell
.\DislinxExec.ps1 -Target 192.168.56.101 -Profile Deep
```

Discovery dapat mencakup:

```text
TCP service discovery
Version detection
Default NSE scripts
HTTP discovery
SMB discovery
Extended TCP discovery
UDP top-port discovery
```

Nmap hanya boleh digunakan terhadap target yang berada dalam scope assessment atau lab.

---

## Interesting Asset Discovery

Salah satu bagian utama DislinxExec adalah asset classification.

Tool tidak hanya menampilkan seluruh file, tetapi mencoba mengidentifikasi file dan directory yang berpotensi relevan untuk assessment berdasarkan metadata.

Contoh kategori:

```text
Configuration
Backup
Database
Development
Application
Logs
Archives
Staging
Testing
Debug
```

File yang dapat menjadi kandidat pemeriksaan:

```text
.config
.conf
.ini
.env
.json
.xml
.yaml
.yml
.bak
.backup
.old
.log
.db
.sqlite
.sqlite3
.sql
.zip
.7z
.rar
.sln
.csproj
```

Contoh output:

```text
[HIGH]
C:\Lab\backup\database.bak

Reason:
backup/archive
interesting directory

Score:
8
```

Contoh lain:

```text
[MEDIUM]
C:\Dev\Project\application.config

Reason:
configuration
development directory

Score:
5
```

Interest score bukan vulnerability score.

Tujuannya hanya membantu tester menentukan asset mana yang layak diperiksa terlebih dahulu.

---

## Asset Correlation

DislinxExec mencoba menghubungkan hasil discovery yang berbeda.

Contoh:

```text
Service
   |
   +-- Apache
   |
   +-- C:\xampp\apache\bin\httpd.exe
   |
   +-- Port 80
   |
   +-- HTTP service
   |
   +-- C:\xampp\htdocs\
```

Hasil seperti ini lebih berguna daripada daftar informasi yang berdiri sendiri karena memberikan gambaran mengenai application environment yang ditemukan.

---

## Output

Setiap execution membuat directory session:

```text
DislinxExec-Results/
└── DislinxExec-20260922-112530/
    |
    +-- findings.json
    +-- findings.csv
    +-- DislinxExec.html
    |
    +-- windows-system.json
    +-- users.csv
    +-- processes.csv
    +-- services.csv
    +-- scheduled-tasks.csv
    +-- software.csv
    +-- network.csv
    +-- tcp-connections.csv
    +-- shares.csv
    +-- firewall.csv
    |
    +-- nmap-common.txt
    +-- nmap-services.txt
    +-- nmap-default-scripts.txt
    +-- nmap-http.txt
    +-- nmap-smb.txt
```

---

## HTML Report

DislinxExec menghasilkan dashboard HTML yang berisi:

```text
Total Findings
High Interest
Medium Interest
Low Interest
Asset
Category
Reason
Interest Score
MITRE Technique
```

Report dapat digunakan untuk melihat hasil discovery tanpa harus membaca seluruh output console.

---

## Scan Profiles

### Quick

Digunakan untuk initial discovery.

```powershell
.\DislinxExec.ps1 `
    -Target 192.168.56.101 `
    -Profile Quick
```

### Standard

Digunakan sebagai mode assessment utama.

```powershell
.\DislinxExec.ps1 `
    -Target 192.168.56.101 `
    -Profile Standard
```

### Deep

Digunakan untuk Windows lab atau environment yang memang berada dalam scope.

```powershell
.\DislinxExec.ps1 `
    -Target 192.168.56.101 `
    -Profile Deep
```

---

## Local Windows Only

Nmap dapat dinonaktifkan:

```powershell
.\DislinxExec.ps1 `
    -Target 127.0.0.1 `
    -NoNmap
```

Mode ini tetap menjalankan Windows discovery dan local asset discovery.

---

## CTF / Lab Example

Contoh environment:

```text
             Lab Network

        +------------------+
        |   Kali / Tester  |
        +--------+---------+
                 |
                 |
        +--------+---------+
        | Windows Lab VM   |
        | 192.168.56.101   |
        +------------------+
```

Jalankan dari Windows:

```powershell
.\DislinxExec.ps1 `
    -Target 192.168.56.101 `
    -Profile Deep
```

Kemudian periksa:

```text
DislinxExec.html
```

dan gunakan hasil discovery sebagai dasar untuk manual assessment.

---

## MITRE ATT&CK Coverage

| Technique                              | ID    |
| -------------------------------------- | ----- |
| System Information Discovery           | T1082 |
| System Owner/User Discovery            | T1033 |
| Permission Groups Discovery            | T1069 |
| Process Discovery                      | T1057 |
| System Service Discovery               | T1007 |
| System Network Configuration Discovery | T1016 |
| System Network Connections Discovery   | T1049 |
| Network Share Discovery                | T1135 |
| Software Discovery                     | T1518 |
| File and Directory Discovery           | T1083 |
| Scheduled Task/Job                     | T1053 |

---

## Requirements

```text
Windows 10
Windows 11
Windows Server
PowerShell 5.1+
```

Optional:

```text
Nmap
```

Nmap tidak diperlukan untuk local Windows discovery.

---

## Installation

Clone repository:

```powershell
git clone https://github.com/USERNAME/DislinxExec.git
cd DislinxExec
```

Allow script execution untuk sesi PowerShell saat ini:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
```

Jalankan:

```powershell
.\DislinxExec.ps1 -Target 127.0.0.1
```

---

## Security Scope

DislinxExec dibuat untuk:

```text
Authorized Penetration Testing
CTF
Windows Security Labs
Internal Security Assessment
Security Research
```

Tool tidak melakukan:

```text
Password dumping
Credential extraction
Browser cookie theft
Token theft
Private-key extraction
Remote command execution
Automated lateral movement
```

Nmap hanya dijalankan terhadap target yang diberikan secara eksplisit oleh operator.

---

## Roadmap

```text
[x] Windows host discovery
[x] User and group discovery
[x] Process discovery
[x] Service discovery
[x] Network discovery
[x] SMB discovery
[x] HTTP discovery
[x] Nmap integration
[x] Interesting asset detection
[x] Asset scoring
[x] Asset correlation
[x] MITRE ATT&CK mapping
[x] JSON reporting
[x] CSV reporting
[x] HTML reporting

[ ] Custom discovery profiles
[ ] MITRE ATT&CK matrix view
[ ] Asset relationship graph
[ ] Historical scan comparison
[ ] Scan result diff
[ ] Plugin engine
```

---

## Disclaimer

DislinxExec dibuat untuk security assessment, CTF, security research, dan environment yang telah mendapatkan izin pengujian.

Jangan gunakan tool terhadap sistem atau jaringan yang berada di luar scope pengujian.

---

## Project

```text
DISLINXEXEC

Windows Discovery & Asset Assessment Engine

Discover
    |
Correlate
    |
Prioritize
    |
Assess
```
