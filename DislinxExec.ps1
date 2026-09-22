# ==============================================================
# DISLINXEXEC
# Windows Discovery & Asset Assessment Engine
# Version: 2.0
#
# Authorized pentest / CTF / lab use only.
#
# Features:
#   - Target validation
#   - Tool detection
#   - Nmap service discovery
#   - Nmap default scripts
#   - SMB discovery
#   - HTTP discovery
#   - Windows local inventory
#   - Interesting asset detection
#   - Application/service correlation
#   - Interest scoring
#   - JSON / CSV / HTML reporting
#
# Does NOT:
#   - dump credentials
#   - extract passwords
#   - steal browser cookies
#   - extract tokens/private keys
#   - execute commands on remote hosts
#   - perform lateral movement
# ==============================================================

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Target,

    [ValidateSet("Quick","Standard","Deep")]
    [string]$Profile = "Standard",

    [string]$Output = ".\DislinxExec-Results",

    [switch]$NoNmap
)

$ErrorActionPreference = "SilentlyContinue"

$Version = "2.0"
$Started = Get-Date
$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"

$Session = Join-Path $Output "DislinxExec-$Stamp"

New-Item -ItemType Directory -Path $Session -Force | Out-Null

$Findings = [System.Collections.Generic.List[object]]::new()
$Artifacts = [System.Collections.Generic.List[object]]::new()

# ==============================================================
# UI
# ==============================================================

function Show-Banner {

    Clear-Host

    Write-Host ""
    Write-Host " ██████╗ ██╗███████╗██╗     ██╗███╗   ██╗██╗  ██╗"
    Write-Host " ██╔══██╗██║██╔════╝██║     ██║████╗  ██║╚██╗██╔╝"
    Write-Host " ██║  ██║██║███████╗██║     ██║██╔██╗ ██║ ╚███╔╝ "
    Write-Host " ██║  ██║██║╚════██║██║     ██║██║╚██╗██║ ██╔██╗ "
    Write-Host " ██████╔╝██║███████║███████╗██║██║ ╚████║██╔╝ ██╗"
    Write-Host " ╚═════╝ ╚═╝╚══════╝╚══════╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝"
    Write-Host ""
    Write-Host "       Windows Discovery & Asset Assessment Engine"
    Write-Host "                     Version $Version"
    Write-Host ""
    Write-Host " Target  : $Target"
    Write-Host " Profile : $Profile"
    Write-Host " Output  : $Session"
    Write-Host ""
    Write-Host "=============================================================="
}

function Section {
    param([string]$Name)

    Write-Host ""
    Write-Host "[$Name]" -ForegroundColor Cyan
    Write-Host ("-" * 62)
}

function Add-Finding {

    param(
        [string]$Category,
        [string]$Severity,
        [string]$Asset,
        [string]$Reason,
        [int]$Score = 0,
        [string]$MITRE = ""
    )

    $finding = [PSCustomObject]@{
        Time     = Get-Date
        Category = $Category
        Severity = $Severity
        Score    = $Score
        Asset    = $Asset
        Reason   = $Reason
        MITRE    = $MITRE
    }

    $Findings.Add($finding)

    switch ($Severity) {
        "HIGH" {
            Write-Host "[HIGH]   $Asset :: $Reason" -ForegroundColor Red
        }

        "MEDIUM" {
            Write-Host "[MEDIUM] $Asset :: $Reason" -ForegroundColor Yellow
        }

        "LOW" {
            Write-Host "[LOW]    $Asset :: $Reason" -ForegroundColor DarkYellow
        }

        default {
            Write-Host "[INFO]   $Asset :: $Reason"
        }
    }
}

# ==============================================================
# TOOLING
# ==============================================================

function Test-Tool {

    param([string]$Name)

    $cmd = Get-Command $Name -ErrorAction SilentlyContinue

    if ($cmd) {
        Write-Host "[+] $Name : $($cmd.Source)"
        return $true
    }

    Write-Host "[-] $Name : not installed"
    return $false
}

$HasNmap = $false

if (-not $NoNmap) {
    $HasNmap = Test-Tool "nmap"
}

# ==============================================================
# TARGET VALIDATION
# ==============================================================

function Test-Target {

    Section "TARGET VALIDATION"

    Write-Host "[*] Target: $Target"

    $resolved = $null

    try {
        $resolved = [System.Net.Dns]::GetHostAddresses($Target)
    }
    catch {}

    if ($resolved) {

        foreach ($ip in $resolved) {

            Write-Host "[+] Resolved: $ip"

            $Artifacts.Add([PSCustomObject]@{
                Type  = "DNS"
                Value = "$ip"
            })
        }
    }
    else {
        Write-Host "[!] DNS resolution unavailable."
    }

    try {

        $ping = Test-Connection `
            -ComputerName $Target `
            -Count 1 `
            -Quiet

        if ($ping) {
            Write-Host "[+] ICMP: reachable"
        }
        else {
            Write-Host "[!] ICMP: no response"
        }

    }
    catch {}
}

# ==============================================================
# NMAP ENGINE
# ==============================================================

function Invoke-Nmap {

    param(
        [string]$Name,
        [string[]]$Arguments,
        [string]$OutputFile
    )

    if (-not $HasNmap) {
        return
    }

    Section "NMAP :: $Name"

    Write-Host "[*] nmap $($Arguments -join ' ')"

    $out = Join-Path $Session $OutputFile

    & nmap @Arguments 2>&1 |
        Tee-Object -FilePath $out

    $Artifacts.Add([PSCustomObject]@{
        Type = "Nmap"
        Name = $Name
        File = $out
    })
}

function Start-NetworkAssessment {

    if (-not $HasNmap) {
        Write-Host "[!] Nmap unavailable - network stage skipped."
        return
    }

    # Quick:
    # common service discovery
    Invoke-Nmap `
        "Common Services" `
        @(
            "-sV",
            "--open",
            "--top-ports",
            "100",
            $Target
        ) `
        "nmap-common.txt"

    if ($Profile -eq "Quick") {
        return
    }

    # Standard:
    Invoke-Nmap `
        "Service Enumeration" `
        @(
            "-sV",
            "--version-light",
            "--open",
            $Target
        ) `
        "nmap-services.txt"

    Invoke-Nmap `
        "Default NSE Discovery" `
        @(
            "-sC",
            "-sV",
            "--open",
            $Target
        ) `
        "nmap-default-scripts.txt"

    Invoke-Nmap `
        "HTTP Discovery" `
        @(
            "-p",
            "80,81,443,8000,8080,8081,8443,8888",
            "--script",
            "http-title,http-headers",
            $Target
        ) `
        "nmap-http.txt"

    Invoke-Nmap `
        "SMB Discovery" `
        @(
            "-p",
            "139,445",
            "--script",
            "smb-protocols,smb2-security-mode",
            $Target
        ) `
        "nmap-smb.txt"

    if ($Profile -eq "Deep") {

        Invoke-Nmap `
            "Extended TCP Discovery" `
            @(
                "-sV",
                "--open",
                "-p-",
                "--min-rate",
                "1000",
                $Target
            ) `
            "nmap-all-tcp.txt"

        Invoke-Nmap `
            "UDP Top Ports" `
            @(
                "-sU",
                "--top-ports",
                "50",
                "--open",
                $Target
            ) `
            "nmap-udp.txt"
    }
}

# ==============================================================
# LOCAL WINDOWS DISCOVERY
# ==============================================================

function Get-WindowsDiscovery {

    Section "WINDOWS HOST DISCOVERY"

    $computer = Get-CimInstance Win32_ComputerSystem
    $os = Get-CimInstance Win32_OperatingSystem

    $system = [PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME
        Domain       = $computer.Domain
        Manufacturer = $computer.Manufacturer
        Model        = $computer.Model
        OS           = $os.Caption
        Version      = $os.Version
        Build        = $os.BuildNumber
        Architecture = $os.OSArchitecture
        LastBoot     = $os.LastBootUpTime
        RAM_GB       = [math]::Round(
            $computer.TotalPhysicalMemory / 1GB,
            2
        )
    }

    $system |
        Format-List

    $system |
        ConvertTo-Json |
        Set-Content (Join-Path $Session "windows-system.json")

    Add-Finding `
        "Host" `
        "INFO" `
        $system.ComputerName `
        "$($system.OS) build $($system.Build)" `
        1 `
        "T1082"

    # ----------------------------------------------------------
    # USERS
    # ----------------------------------------------------------

    Write-Host "[*] Users"

    $users = Get-CimInstance Win32_UserAccount |
        Select-Object Name,Domain,Disabled,Lockout,LocalAccount,SID

    $users |
        Export-Csv `
            (Join-Path $Session "users.csv") `
            -NoTypeInformation

    foreach ($user in $users) {

        if (-not $user.Disabled) {

            Add-Finding `
                "Account" `
                "INFO" `
                "$($user.Domain)\$($user.Name)" `
                "Enabled account" `
                1 `
                "T1033"
        }
    }

    # ----------------------------------------------------------
    # PROCESSES
    # ----------------------------------------------------------

    Write-Host "[*] Processes"

    $processes = Get-CimInstance Win32_Process |
        Select-Object ProcessId,
                      ParentProcessId,
                      Name,
                      ExecutablePath,
                      CommandLine

    $processes |
        Export-Csv `
            (Join-Path $Session "processes.csv") `
            -NoTypeInformation

    foreach ($process in $processes) {

        if ($process.ExecutablePath -and
            $process.ExecutablePath -notlike "$env:WINDIR\*") {

            Add-Finding `
                "Process" `
                "LOW" `
                $process.ExecutablePath `
                "Non-system executable" `
                2 `
                "T1057"
        }
    }

    # ----------------------------------------------------------
    # SERVICES
    # ----------------------------------------------------------

    Write-Host "[*] Services"

    $services = Get-CimInstance Win32_Service |
        Select-Object Name,
                      DisplayName,
                      State,
                      StartMode,
                      StartName,
                      PathName

    $services |
        Export-Csv `
            (Join-Path $Session "services.csv") `
            -NoTypeInformation

    foreach ($service in $services) {

        if ($service.State -eq "Running") {

            Add-Finding `
                "Service" `
                "INFO" `
                $service.Name `
                "Running service" `
                1 `
                "T1007"
        }

        if ($service.PathName -match "Program Files|AppData|Temp") {

            Add-Finding `
                "Service" `
                "MEDIUM" `
                $service.Name `
                "Service executable located outside typical Windows system paths" `
                4 `
                "T1007"
        }
    }

    # ----------------------------------------------------------
    # SCHEDULED TASKS
    # ----------------------------------------------------------

    Write-Host "[*] Scheduled Tasks"

    $tasks = Get-ScheduledTask |
        Select-Object TaskName,TaskPath,State

    $tasks |
        Export-Csv `
            (Join-Path $Session "scheduled-tasks.csv") `
            -NoTypeInformation

    # ----------------------------------------------------------
    # SOFTWARE
    # ----------------------------------------------------------

    Write-Host "[*] Installed Software"

    $softwarePaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    $software = foreach ($path in $softwarePaths) {

        Get-ItemProperty $path |
            Where-Object DisplayName |
            Select-Object DisplayName,
                          DisplayVersion,
                          Publisher,
                          InstallDate,
                          InstallLocation
    }

    $software |
        Sort-Object DisplayName -Unique |
        Export-Csv `
            (Join-Path $Session "software.csv") `
            -NoTypeInformation
}

# ==============================================================
# NETWORK INVENTORY
# ==============================================================

function Get-NetworkInventory {

    Section "LOCAL NETWORK INVENTORY"

    $interfaces = Get-NetIPConfiguration

    foreach ($interface in $interfaces) {

        $obj = [PSCustomObject]@{
            Interface = $interface.InterfaceAlias
            IPv4      = ($interface.IPv4Address.IPAddress -join ",")
            IPv6      = ($interface.IPv6Address.IPAddress -join ",")
            Gateway   = ($interface.IPv4DefaultGateway.NextHop -join ",")
            DNS       = ($interface.DNSServer.ServerAddresses -join ",")
        }

        $Artifacts.Add($obj)
    }

    $Artifacts |
        Where-Object Interface |
        Export-Csv `
            (Join-Path $Session "network.csv") `
            -NoTypeInformation

    Write-Host "[*] Active TCP connections"

    Get-NetTCPConnection |
        Select-Object LocalAddress,
                      LocalPort,
                      RemoteAddress,
                      RemotePort,
                      State,
                      OwningProcess |
        Export-Csv `
            (Join-Path $Session "tcp-connections.csv") `
            -NoTypeInformation
}

# ==============================================================
# ASSET DISCOVERY
# ==============================================================

function Search-InterestingAssets {

    Section "INTERESTING ASSET DISCOVERY"

    $roots = @(
        "$env:USERPROFILE\Desktop",
        "$env:USERPROFILE\Documents",
        "$env:USERPROFILE\Downloads",
        "$env:USERPROFILE\source",
        "$env:USERPROFILE\Projects",
        "C:\inetpub",
        "C:\xampp",
        "C:\wamp64"
    )

    $patterns = @(
        "*.config",
        "*.conf",
        "*.ini",
        "*.json",
        "*.xml",
        "*.yaml",
        "*.yml",
        "*.env",
        "*.bak",
        "*.backup",
        "*.old",
        "*.log",
        "*.db",
        "*.sqlite",
        "*.sqlite3",
        "*.sql",
        "*.zip",
        "*.7z",
        "*.rar",
        "*.sln",
        "*.csproj",
        "*.dockerfile"
    )

    $seen = @{}

    foreach ($root in $roots) {

        if (-not (Test-Path $root)) {
            continue
        }

        Write-Host "[*] Indexing $root"

        foreach ($pattern in $patterns) {

            Get-ChildItem `
                -Path $root `
                -Filter $pattern `
                -File `
                -Recurse `
                -Force `
                -ErrorAction SilentlyContinue |
            ForEach-Object {

                if ($seen.ContainsKey($_.FullName)) {
                    return
                }

                $seen[$_.FullName] = $true

                $score = 0
                $reasons = New-Object System.Collections.Generic.List[string]

                $name = $_.Name.ToLower()
                $path = $_.FullName.ToLower()
                $ext  = $_.Extension.ToLower()

                # File type
                if ($ext -in @(
                    ".config",".conf",".ini",".env",
                    ".json",".yaml",".yml",".xml"
                )) {

                    $score += 3
                    $reasons.Add("configuration")
                }

                # Backup/archive
                if ($ext -in @(
                    ".bak",".backup",".old",".zip",
                    ".7z",".rar"
                )) {

                    $score += 4
                    $reasons.Add("backup/archive")
                }

                # Database
                if ($ext -in @(
                    ".db",".sqlite",".sqlite3",".sql"
                )) {

                    $score += 4
                    $reasons.Add("database-related")
                }

                # Development
                if ($ext -in @(
                    ".sln",".csproj",".ps1",".py",
                    ".php",".js"
                )) {

                    $score += 2
                    $reasons.Add("development artifact")
                }

                # Interesting path
                if ($path -match
                    "\\backup\\|\\backups\\|\\old\\|\\archive\\|\\staging\\|\\dev\\|\\test\\|\\debug\\") {

                    $score += 3
                    $reasons.Add("interesting directory")
                }

                # Interesting filename
                if ($name -match
                    "config|setting|database|backup|debug|staging|development") {

                    $score += 3
                    $reasons.Add("interesting filename")
                }

                $severity = "LOW"

                if ($score -ge 8) {
                    $severity = "HIGH"
                }
                elseif ($score -ge 5) {
                    $severity = "MEDIUM"
                }

                Add-Finding `
                    "Asset" `
                    $severity `
                    $_.FullName `
                    ($reasons -join ", ") `
                    $score `
                    "T1083"
            }
        }
    }
}

# ==============================================================
# SHARES
# ==============================================================

function Get-ShareInventory {

    Section "SHARE DISCOVERY"

    $shares = Get-SmbShare |
        Select-Object Name,
                      Path,
                      Description,
                      ScopeName

    $shares |
        Export-Csv `
            (Join-Path $Session "shares.csv") `
            -NoTypeInformation

    foreach ($share in $shares) {

        Add-Finding `
            "Share" `
            "MEDIUM" `
            $share.Name `
            "Local SMB share: $($share.Path)" `
            3 `
            "T1135"
    }
}

# ==============================================================
# SECURITY CONFIGURATION
# ==============================================================

function Get-SecurityInventory {

    Section "SECURITY CONFIGURATION"

    $firewall = Get-NetFirewallProfile |
        Select-Object Name,
                      Enabled,
                      DefaultInboundAction,
                      DefaultOutboundAction

    $firewall |
        Export-Csv `
            (Join-Path $Session "firewall.csv") `
            -NoTypeInformation

    foreach ($profile in $firewall) {

        if (-not $profile.Enabled) {

            Add-Finding `
                "Security" `
                "MEDIUM" `
                $profile.Name `
                "Windows Firewall profile disabled" `
                4
        }
    }

    if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {

        $defender = Get-MpComputerStatus |
            Select-Object AMServiceEnabled,
                          AntivirusEnabled,
                          RealTimeProtectionEnabled,
                          IoavProtectionEnabled

        $defender |
            ConvertTo-Json |
            Set-Content (Join-Path $Session "defender.json")
    }
}

# ==============================================================
# CORRELATION
# ==============================================================

function Invoke-Correlation {

    Section "ASSET CORRELATION"

    Write-Host "[*] Correlating discovered services and local assets..."

    $serviceData = Get-CimInstance Win32_Service

    foreach ($service in $serviceData) {

        $path = $service.PathName

        if (-not $path) {
            continue
        }

        if ($path -match
            "xampp|apache|nginx|iis|node|python|php|mysql|postgres|mssql|redis") {

            Add-Finding `
                "Application" `
                "MEDIUM" `
                $service.Name `
                "Application/service stack detected: $path" `
                4 `
                "T1518"
        }
    }

    $softwareData = Import-Csv `
        (Join-Path $Session "software.csv")

    foreach ($app in $softwareData) {

        if ($app.DisplayName -match
            "Apache|Nginx|IIS|PHP|Python|Node|MySQL|PostgreSQL|SQL Server|Docker|Git") {

            Add-Finding `
                "Software" `
                "INFO" `
                $app.DisplayName `
                "Development/server software detected: $($app.DisplayVersion)" `
                2 `
                "T1518"
        }
    }
}

# ==============================================================
# REPORT
# ==============================================================

function New-Report {

    Section "REPORT GENERATION"

    $json = Join-Path $Session "findings.json"
    $csv  = Join-Path $Session "findings.csv"
    $html = Join-Path $Session "DislinxExec.html"

    $Findings |
        ConvertTo-Json -Depth 8 |
        Set-Content $json -Encoding UTF8

    $Findings |
        Export-Csv $csv -NoTypeInformation -Encoding UTF8

    $high = @(
        $Findings |
        Where-Object Severity -eq "HIGH"
    ).Count

    $medium = @(
        $Findings |
        Where-Object Severity -eq "MEDIUM"
    ).Count

    $low = @(
        $Findings |
        Where-Object Severity -eq "LOW"
    ).Count

    $info = @(
        $Findings |
        Where-Object Severity -eq "INFO"
    ).Count

    $rows = foreach ($f in $Findings) {

        "<tr>
        <td>$($f.Severity)</td>
        <td>$($f.Score)</td>
        <td>$($f.Category)</td>
        <td>$([System.Net.WebUtility]::HtmlEncode($f.Asset))</td>
        <td>$([System.Net.WebUtility]::HtmlEncode($f.Reason))</td>
        <td>$($f.MITRE)</td>
        </tr>"
    }

    $htmlContent = @"
<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<title>DislinxExec Assessment</title>

<style>

body {
    background:#0b0f14;
    color:#e6edf3;
    font-family:Segoe UI,Arial,sans-serif;
    margin:35px;
}

h1 {
    font-size:34px;
    margin-bottom:4px;
}

.subtitle {
    color:#8b949e;
    margin-bottom:30px;
}

.grid {
    display:grid;
    grid-template-columns:repeat(4,1fr);
    gap:15px;
    margin-bottom:30px;
}

.card {
    background:#161b22;
    border:1px solid #30363d;
    border-radius:10px;
    padding:20px;
}

.number {
    font-size:32px;
    font-weight:bold;
    margin-top:8px;
}

table {
    width:100%;
    border-collapse:collapse;
    background:#0d1117;
}

th {
    background:#161b22;
    text-align:left;
}

th,td {
    padding:11px;
    border-bottom:1px solid #21262d;
    vertical-align:top;
}

td {
    font-size:13px;
}

</style>

</head>

<body>

<h1>DISLINXEXEC</h1>

<div class="subtitle">
Windows Discovery & Asset Assessment Engine<br>
Target: $Target<br>
Profile: $Profile<br>
Generated: $(Get-Date)
</div>

<div class="grid">

<div class="card">
HIGH
<div class="number">$high</div>
</div>

<div class="card">
MEDIUM
<div class="number">$medium</div>
</div>

<div class="card">
LOW
<div class="number">$low</div>
</div>

<div class="card">
TOTAL
<div class="number">$($Findings.Count)</div>
</div>

</div>

<table>

<thead>

<tr>
<th>Severity</th>
<th>Score</th>
<th>Category</th>
<th>Asset</th>
<th>Reason</th>
<th>MITRE</th>
</tr>

</thead>

<tbody>

$($rows -join "`n")

</tbody>

</table>

</body>

</html>
"@

    Set-Content $html $htmlContent -Encoding UTF8

    Write-Host ""
    Write-Host "=============================================================="
    Write-Host "                    DISLINXEXEC COMPLETE"
    Write-Host "=============================================================="
    Write-Host ""
    Write-Host " HIGH     : $high"
    Write-Host " MEDIUM   : $medium"
    Write-Host " LOW      : $low"
    Write-Host " INFO     : $info"
    Write-Host " TOTAL    : $($Findings.Count)"
    Write-Host ""
    Write-Host " HTML     : $html"
    Write-Host " JSON     : $json"
    Write-Host " CSV      : $csv"
    Write-Host ""
    Write-Host "=============================================================="
}

# ==============================================================
# MAIN
# ==============================================================

Show-Banner

Test-Target

Start-NetworkAssessment

Get-WindowsDiscovery

Get-NetworkInventory

Get-ShareInventory

Get-SecurityInventory

Search-InterestingAssets

Invoke-Correlation

New-Report

Write-Host ""
Write-Host "[+] DislinxExec finished successfully."
