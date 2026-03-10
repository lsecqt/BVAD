#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs the latest SQL Server and configures it with intentional vulnerabilities for lab/pentest training.

.DESCRIPTION
    This script:
      1. Downloads and installs the latest SQL Server Developer/Evaluation edition
      2. Configures intentional misconfigurations for the following attack scenarios:
         - Bruteforcable SA account (weak password)
         - SA password == Local Admin password
         - Local admin user without LAPS
         - xp_cmdshell enabled (RCE)
         - sp_start_job abuse (RCE)
         - xp_dirtree enabled (NTLM relay/capture)
         - MSSQL running as a service account with SeImpersonatePrivilege
         - WinRM enabled with a credentialed user (initial access)
         - Mixed mode authentication (SQL + Windows)

    SQL02 linked server setup is excluded (not yet present).

.PARAMETER MachineName
    The hostname of the machine. Auto-detected from \$env:COMPUTERNAME if not specified.

.PARAMETER WeakPassword
    The weak password to set for SA, local admin, and the WinRM user.
    Defaults to 'Password123!'

.PARAMETER LocalAdminUsername
    The local admin account to create (no LAPS). Defaults to 'sqladmin'.

.PARAMETER WinRMUsername
    The Windows user that can WinRM into the box. Defaults to 'labuser'.

.PARAMETER SqlServiceAccount
    The local account MSSQL will run as (gets SeImpersonatePrivilege). Defaults to 'svc_mssql'.

.EXAMPLE
    # Auto-detect machine name (recommended)
    .\Setup-VulnerableMSSQL.ps1

#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$MachineName = $env:COMPUTERNAME,

    [string]$WeakPassword        = "Password123!",
    [string]$LocalAdminUsername  = "sqladmin",
    [string]$WinRMUsername       = "labuser",
    [string]$SqlServiceAccount   = "svc_mssql"
)

$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"

# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────
function Write-Banner {
    param([string]$Text)
    $line = "=" * 60
    Write-Host ""
    Write-Host $line -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host $line -ForegroundColor Cyan
}

function Write-Step {
    param([string]$Text)
    Write-Host "[*] $Text" -ForegroundColor Yellow
}

function Write-OK {
    param([string]$Text)
    Write-Host "[+] $Text" -ForegroundColor Green
}

# ─────────────────────────────────────────────
# Step state tracking (idempotency)
# ─────────────────────────────────────────────
$StateFile = "$env:TEMP\VulnMSSQL_State.txt"

function Get-StepDone {
    param([string]$StepKey)
    if (-not (Test-Path $StateFile)) { return $false }
    return (Get-Content $StateFile) -contains $StepKey
}

function Set-StepDone {
    param([string]$StepKey)
    Add-Content -Path $StateFile -Value $StepKey
}

function Skip-IfDone {
    param([string]$StepKey, [string]$Label)
    if (Get-StepDone $StepKey) {
        Write-Host "[~] SKIPPING (already done): $Label" -ForegroundColor DarkGray
        return $true
    }
    return $false
}

# ─────────────────────────────────────────────
# 0. Pre-flight
# ─────────────────────────────────────────────
Write-Banner "Setup-VulnerableMSSQL.ps1  |  Target: $MachineName"
Write-Step "Checking prerequisites..."

# Ensure sqlcmd available after install; continue for now
$sqlcmdAvailable = $false
if (Get-Command sqlcmd -ErrorAction SilentlyContinue) { $sqlcmdAvailable = $true }

# ─────────────────────────────────────────────
# 1. Download & Install SQL Server (latest Evaluation)
# ─────────────────────────────────────────────
Write-Banner "Step 1 — Download & Install SQL Server"

if (Skip-IfDone "STEP1" "SQL Server Install") {
    # Still need svcName for later steps
} else {

$installerExe = "$env:TEMP\SQLServerSetup.exe"
$sqlIsoPath   = "$env:TEMP\SQLEVAL"

# Microsoft's official SQL Server 2022 Evaluation download URL
$downloadUrl = "https://go.microsoft.com/fwlink/p/?linkid=2215158&clcid=0x409&culture=en-us&country=us"

if (-not (Test-Path $installerExe)) {
    Write-Step "Downloading SQL Server Evaluation installer..."
    Invoke-WebRequest -Uri $downloadUrl -OutFile $installerExe -UseBasicParsing
    Write-OK "Downloaded to $installerExe"
} else {
    Write-OK "Installer already present, skipping download."
}

# Use the bootstrapper to download the full media then install
Write-Step "Extracting SQL Server media to $sqlIsoPath ..."
Start-Process -FilePath $installerExe `
    -ArgumentList "/ACTION=Download", "/MEDIAPATH=$sqlIsoPath", "/MEDIATYPE=ISO", "/QUIET" `
    -Wait -NoNewWindow

$isoFile = Get-ChildItem -Path $sqlIsoPath -Filter "*.iso" | Select-Object -First 1
if (-not $isoFile) {
    # Some versions extract directly as a folder with setup.exe
    $setupExe = Get-ChildItem -Path $sqlIsoPath -Recurse -Filter "setup.exe" | Select-Object -First 1
} else {
    Write-Step "Mounting ISO $($isoFile.FullName) ..."
    $mount     = Mount-DiskImage -ImagePath $isoFile.FullName -PassThru
    $driveLetter = ($mount | Get-Volume).DriveLetter
    $setupExe  = Get-Item "${driveLetter}:\setup.exe"
}

if (-not $setupExe) { throw "Could not locate setup.exe after extraction." }
Write-OK "Found setup.exe at $($setupExe.FullName)"

Write-Step "Installing SQL Server (this may take several minutes)..."

# Build service account: use local account .\svc_mssql
# We create this account AFTER install since setup can accept a local account
# For simplicity, use NT AUTHORITY\NETWORK SERVICE for the engine, then swap to svc_mssql post-install
$installArgs = @(
    "/Q"
    "/ACTION=Install"
    "/FEATURES=SQLEngine,SQLAgentSvc"
    "/INSTANCENAME=$MachineName"
    "/SQLSVCACCOUNT=`"NT AUTHORITY\NETWORK SERVICE`""
    "/AGTSVCACCOUNT=`"NT AUTHORITY\NETWORK SERVICE`""
    "/SQLSYSADMINACCOUNTS=`"BUILTIN\Administrators`""
    "/SECURITYMODE=SQL"
    "/SAPWD=`"$WeakPassword`""
    "/TCPENABLED=1"
    "/NPENABLED=1"
    "/IACCEPTSQLSERVERLICENSETERMS"
    "/UPDATEENABLED=0"
)

$proc = Start-Process -FilePath $setupExe.FullName `
    -ArgumentList $installArgs `
    -Wait -NoNewWindow -PassThru

if ($proc.ExitCode -notin @(0, 3010)) {
    Write-Warning "SQL Server setup exited with code $($proc.ExitCode). Check C:\Program Files\Microsoft SQL Server\*\Setup Bootstrap\Log\ for details."
} else {
    Write-OK "SQL Server installed successfully (exit code $($proc.ExitCode))."
    Set-StepDone "STEP1"
}

# Unmount ISO if we mounted one
if ($isoFile) {
    Dismount-DiskImage -ImagePath $isoFile.FullName | Out-Null
}

# Reload PATH so sqlcmd is available
$env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine")
Start-Sleep -Seconds 5

} # end STEP1

# ─────────────────────────────────────────────
# 2. Ensure SQL Server service is running
# ─────────────────────────────────────────────
Write-Banner "Step 2 — Start SQL Server Service"

# Instance name == MachineName, so service is always MSSQL$<MachineName>
$svcName = "MSSQL`$$MachineName"

if (-not (Skip-IfDone "STEP2" "SQL Server Service Start")) {
    Write-Step "Starting service $svcName ..."
    Set-Service -Name $svcName -StartupType Automatic
    Start-Service -Name $svcName
    Write-OK "Service $svcName is running."
    Start-Sleep -Seconds 8   # give SQL time to fully initialize
    Set-StepDone "STEP2"
} else {
    # Ensure svcName is always set even when skipping
    # Instance name == MachineName, so service is always MSSQL$<MachineName>
$svcName = "MSSQL`$$MachineName"
}

# ─────────────────────────────────────────────
# 3. Create Local Users (no LAPS, weak passwords)
# ─────────────────────────────────────────────
Write-Banner "Step 3 — Create Local Accounts"

if (-not (Skip-IfDone "STEP3" "Create Local Accounts")) {

function New-WeakLocalUser {
    param([string]$Username, [string]$Password, [switch]$IsAdmin)

    # Use net.exe commands — avoids all PS cmdlet bool-parameter quirks on Server 2019
    $userExists = Get-LocalUser -Name $Username -ErrorAction SilentlyContinue
    if ($userExists) {
        Write-Step "User '$Username' already exists, resetting password..."
        & net user $Username $Password | Out-Null
    } else {
        & net user $Username $Password /add /comment:"Lab-intentionally-weak" | Out-Null
        Write-OK "Created local user: $Username"
    }

    # Set password never expires via wmic (no PS bool-parameter issues)
    & wmic useraccount where "Name='$Username'" set PasswordExpires=FALSE 2>&1 | Out-Null

    if ($IsAdmin) {
        & net localgroup Administrators $Username /add 2>&1 | Out-Null
        Write-OK "Added '$Username' to local Administrators (no LAPS)."
    }
}

# Local admin without LAPS — password == SA password
New-WeakLocalUser -Username $LocalAdminUsername -Password $WeakPassword -IsAdmin

# WinRM-capable user (not necessarily admin — initial foothold via creds)
New-WeakLocalUser -Username $WinRMUsername -Password $WeakPassword
Add-LocalGroupMember -Group "Remote Management Users" -Member $WinRMUsername -ErrorAction SilentlyContinue
Write-OK "Added '$WinRMUsername' to Remote Management Users."

# SQL service account
New-WeakLocalUser -Username $SqlServiceAccount -Password $WeakPassword
Write-OK "Created SQL service account: $SqlServiceAccount"

Set-StepDone "STEP3"
} # end STEP3

# ─────────────────────────────────────────────
# 4. Assign SeImpersonatePrivilege to SQL service account
# ─────────────────────────────────────────────
Write-Banner "Step 4 — SeImpersonatePrivilege for $SqlServiceAccount"

if (-not (Skip-IfDone "STEP4" "SeImpersonatePrivilege")) {

Write-Step "Exporting current security policy..."
$tmpCfg  = "$env:TEMP\secpol_export.cfg"
$tmpMod  = "$env:TEMP\secpol_modified.cfg"
secedit /export /cfg $tmpCfg /quiet

$content = Get-Content $tmpCfg -Raw

# Locate SeImpersonatePrivilege line and append our user
if ($content -match "SeImpersonatePrivilege\s*=\s*(.*)") {
    $existing = $matches[1].Trim()
    if ($existing -notlike "*$SqlServiceAccount*") {
        $newLine  = "SeImpersonatePrivilege = $existing,*$MachineName\$SqlServiceAccount"
        $content  = $content -replace "SeImpersonatePrivilege\s*=\s*(.*)", $newLine
    }
} else {
    $content += "`r`n[Privilege Rights]`r`nSeImpersonatePrivilege = *$MachineName\$SqlServiceAccount`r`n"
}

$content | Set-Content $tmpMod -Encoding Unicode
secedit /configure /db "$env:TEMP\secedit.sdb" /cfg $tmpMod /quiet
Write-OK "SeImpersonatePrivilege granted to $SqlServiceAccount."

# Also assign SeAssignPrimaryTokenPrivilege
Write-Step "Granting SeAssignPrimaryTokenPrivilege..."
$content2 = Get-Content $tmpMod -Raw
if ($content2 -match "SeAssignPrimaryTokenPrivilege\s*=\s*(.*)") {
    $existing2 = $matches[1].Trim()
    if ($existing2 -notlike "*$SqlServiceAccount*") {
        $newLine2 = "SeAssignPrimaryTokenPrivilege = $existing2,*$MachineName\$SqlServiceAccount"
        $content2 = $content2 -replace "SeAssignPrimaryTokenPrivilege\s*=\s*(.*)", $newLine2
    }
} else {
    $content2 += "`r`nSeAssignPrimaryTokenPrivilege = *$MachineName\$SqlServiceAccount`r`n"
}
$content2 | Set-Content $tmpMod -Encoding Unicode
secedit /configure /db "$env:TEMP\secedit.sdb" /cfg $tmpMod /quiet
Write-OK "SeAssignPrimaryTokenPrivilege granted to $SqlServiceAccount."

Set-StepDone "STEP4"
} # end STEP4

# ─────────────────────────────────────────────
# 5. Change SQL Server service to run as svc_mssql
# ─────────────────────────────────────────────
Write-Banner "Step 5 — Configure SQL Engine to Run as $SqlServiceAccount"

if (-not (Skip-IfDone "STEP5" "SQL Service Account Swap")) {
    Write-Step "Updating service logon account for $svcName ..."
    $svcCredential = "$MachineName\$SqlServiceAccount"
    $sc = Get-WmiObject Win32_Service -Filter "Name='$svcName'"
    $sc.Change($null,$null,$null,$null,$null,$null,$svcCredential,$WeakPassword,$null,$null,$null) | Out-Null

    Restart-Service -Name $svcName -Force
    Start-Sleep -Seconds 10
    Write-OK "SQL Server now runs as $svcCredential."
    Set-StepDone "STEP5"
}

# ─────────────────────────────────────────────
# 6. SQL Server Misconfigurations via sqlcmd
# ─────────────────────────────────────────────
Write-Banner "Step 6 — Apply SQL Misconfigurations"

if (-not (Skip-IfDone "STEP6" "SQL Misconfigurations")) {

# Helper: run a T-SQL block and show result
function Invoke-SQL {
    param([string]$Label, [string]$Query)
    Write-Step $Label
    $instance = "localhost\$MachineName"
    $result = sqlcmd -S $instance -d master -U sa -P $WeakPassword -Q $Query -b 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "  SQL error: $result"
    } else {
        Write-OK "  Done: $Label"
    }
}

# 6a. Enable mixed mode (already set via /SECURITYMODE=SQL, but enforce via registry)
Write-Step "Ensuring mixed-mode auth in registry..."
# Auto-detect the correct MSSQL version key (e.g. MSSQL16.SQL01)
$sqlRegKey = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server" |
    Where-Object { $_.PSChildName -match "^MSSQL\d+\.$MachineName$" } |
    Select-Object -First 1 -ExpandProperty PSChildName

if ($sqlRegKey) {
    $mssqlBase = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$sqlRegKey"
    Set-ItemProperty -Path "$mssqlBase\MSSQLServer" -Name "LoginMode" -Value 2 -ErrorAction SilentlyContinue

    # Enable TCP on port 1433 via registry (robust, works when SQL Config Manager isn't available)
    $tcpPath = "$mssqlBase\MSSQLServer\SuperSocketNetLib\Tcp"
    if (Test-Path $tcpPath) {
        Set-ItemProperty -Path $tcpPath -Name "Enabled" -Value 1
        Set-ItemProperty -Path "$tcpPath\IPAll" -Name "TcpPort" -Value "1433"
        Set-ItemProperty -Path "$tcpPath\IPAll" -Name "TcpDynamicPorts" -Value ""
        Write-OK "TCP/IP enabled on port 1433 via registry."
    } else {
        Write-Warning "TCP registry path not found at $tcpPath — SQL may use a dynamic port."
    }
} else {
    Write-Warning "Could not find registry key for instance $MachineName — skipping LoginMode/TCP config."
}
Write-OK "Mixed-mode authentication enabled."

# 6b. Enable SA and set weak password (== local admin password)
Invoke-SQL "Enable SA login with weak password" @"
ALTER LOGIN [sa] ENABLE;
ALTER LOGIN [sa] WITH PASSWORD = '$WeakPassword', CHECK_POLICY = OFF, CHECK_EXPIRATION = OFF;
"@

# 6c. Enable xp_cmdshell (RCE vector)
Invoke-SQL "Enable xp_cmdshell" @"
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
"@

# 6d. Enable Ole Automation Procedures (additional RCE)
Invoke-SQL "Enable Ole Automation Procedures" @"
EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;
"@

# 6e. Create a SQL Agent job for sp_start_job RCE
Invoke-SQL "Create vulnerable SQL Agent job (sp_start_job RCE)" @"
USE msdb;
IF NOT EXISTS (SELECT 1 FROM msdb.dbo.sysjobs WHERE name = 'VulnJob')
BEGIN
    EXEC msdb.dbo.sp_add_job
        @job_name = N'VulnJob',
        @enabled = 1;
    EXEC msdb.dbo.sp_add_jobstep
        @job_name = N'VulnJob',
        @step_name = N'RunCmd',
        @subsystem = N'CmdExec',
        @command = N'whoami > C:\Windows\Temp\vuln_job_output.txt',
        @on_success_action = 1;
    EXEC msdb.dbo.sp_add_jobserver
        @job_name = N'VulnJob',
        @server_name = N'(local)';
END
"@

# 6f. Enable xp_dirtree (NTLM relay/capture via UNC path)
# xp_dirtree is enabled by default; ensure public can execute it
Invoke-SQL "Grant EXECUTE on xp_dirtree to public (NTLM capture)" @"
GRANT EXECUTE ON xp_dirtree TO PUBLIC;
GRANT EXECUTE ON xp_fileexist TO PUBLIC;
"@

# 6g. Create a SQL login with same creds as local admin (stored creds / cred reuse)
Invoke-SQL "Create SQL login mirroring local admin (cred reuse)" @"
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = '$LocalAdminUsername')
BEGIN
    CREATE LOGIN [$LocalAdminUsername] WITH PASSWORD = '$WeakPassword',
        CHECK_POLICY = OFF, CHECK_EXPIRATION = OFF;
    ALTER SERVER ROLE sysadmin ADD MEMBER [$LocalAdminUsername];
END
"@

# 6h. Add WinRM user as a SQL login too (domain auth reuse scenario)
Invoke-SQL "Add WinRM user as SQL login (cred reuse)" @"
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = '$WinRMUsername')
BEGIN
    CREATE LOGIN [$WinRMUsername] WITH PASSWORD = '$WeakPassword',
        CHECK_POLICY = OFF, CHECK_EXPIRATION = OFF;
    ALTER SERVER ROLE sysadmin ADD MEMBER [$WinRMUsername];
END
"@

# 6i. Create a Windows login for the local admin (domain/local auth)
Invoke-SQL "Add local admin as Windows login (mixed auth)" @"
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = '$MachineName\$LocalAdminUsername')
BEGIN
    CREATE LOGIN [$MachineName\$LocalAdminUsername] FROM WINDOWS;
    ALTER SERVER ROLE sysadmin ADD MEMBER [$MachineName\$LocalAdminUsername];
END
"@

# 6j. Store credentials in a database (stored creds scenario)
Invoke-SQL "Create VulnDB with stored credentials table" @"
IF NOT EXISTS (SELECT 1 FROM sys.databases WHERE name = 'VulnDB')
    CREATE DATABASE VulnDB;
"@

Invoke-SQL "Populate stored credentials in VulnDB" @"
USE VulnDB;
IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'AppCredentials')
BEGIN
    CREATE TABLE AppCredentials (
        id       INT IDENTITY PRIMARY KEY,
        app_name NVARCHAR(100),
        username NVARCHAR(100),
        password NVARCHAR(100)   -- plaintext, intentionally vulnerable
    );
    INSERT INTO AppCredentials (app_name, username, password) VALUES
        ('WebApp',    '$WinRMUsername',   '$WeakPassword'),
        ('Monitoring','$LocalAdminUsername','$WeakPassword'),
        ('Backup',    'sa',               '$WeakPassword');
END
"@

# 6k. Enable SQL Server Browser service (discovery)
Write-Step "Enabling SQL Server Browser service..."
Set-Service -Name "SQLBrowser" -StartupType Automatic -ErrorAction SilentlyContinue
Start-Service -Name "SQLBrowser" -ErrorAction SilentlyContinue
Write-OK "SQL Server Browser enabled."

Set-StepDone "STEP6"
} # end STEP6

# ─────────────────────────────────────────────
# 7. Enable & Configure WinRM
# ─────────────────────────────────────────────
Write-Banner "Step 7 — Enable WinRM (Initial Access via Creds)"

if (-not (Skip-IfDone "STEP7" "WinRM Configuration")) {
    Write-Step "Enabling WinRM..."
    Enable-PSRemoting -Force -SkipNetworkProfileCheck | Out-Null
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
    Set-Item WSMan:\localhost\Service\Auth\Basic -Value $true -Force
    Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $true -Force
    Set-Service -Name WinRM -StartupType Automatic
    Restart-Service WinRM
    Write-OK "WinRM enabled. Basic auth allowed (intentionally insecure)."
    Set-StepDone "STEP7"
}

# ─────────────────────────────────────────────
# 8. Firewall Rules
# ─────────────────────────────────────────────
Write-Banner "Step 8 — Open Firewall Ports"

if (-not (Skip-IfDone "STEP8" "Firewall Rules")) {
    $firewallRules = @(
        @{ Name="MSSQL TCP 1433";    Port=1433; Proto="TCP" },
        @{ Name="MSSQL UDP 1434";    Port=1434; Proto="UDP" },
        @{ Name="WinRM HTTP 5985";   Port=5985; Proto="TCP" },
        @{ Name="WinRM HTTPS 5986";  Port=5986; Proto="TCP" },
        @{ Name="SMB 445 (NTLM)";    Port=445;  Proto="TCP" }
    )

    foreach ($rule in $firewallRules) {
        $exists = Get-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue
        if (-not $exists) {
            New-NetFirewallRule -DisplayName $rule.Name `
                -Direction Inbound -Protocol $rule.Proto `
                -LocalPort $rule.Port -Action Allow | Out-Null
        }
        Write-OK "Firewall open: $($rule.Name)"
    }
    Set-StepDone "STEP8"
}

# ─────────────────────────────────────────────
# 9. Disable Windows Defender / AV (lab only!)
# ─────────────────────────────────────────────
Write-Banner "Step 9 — Disable Windows Defender (Lab Environment)"

if (-not (Skip-IfDone "STEP9" "Disable Defender")) {
    Write-Step "Disabling real-time monitoring..."
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableIOAVProtection $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableScriptScanning $true -ErrorAction SilentlyContinue
    Write-OK "Windows Defender real-time monitoring disabled."
    Set-StepDone "STEP9"
}

# ─────────────────────────────────────────────
# 10. Final Summary
# ─────────────────────────────────────────────
Write-Banner "Setup Complete — Attack Surface Summary"

Write-Host @"

  Machine           : $MachineName
  SQL Instance      : $MachineName  (named instance = machine name)
  SQL Version       : SQL Server 2022 Evaluation

  ┌─────────────────────────────────────────────────────┐
  │  CREDENTIALS (all use the same weak password)       │
  ├─────────────────────────────────────────────────────┤
  │  SA login          sa / $WeakPassword
  │  SQL login         $LocalAdminUsername / $WeakPassword
  │  SQL login         $WinRMUsername / $WeakPassword
  │  Local admin       $MachineName\$LocalAdminUsername / $WeakPassword  (no LAPS)
  │  WinRM user        $MachineName\$WinRMUsername / $WeakPassword
  │  SQL svc account   $MachineName\$SqlServiceAccount / $WeakPassword
  └─────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────┐
  │  ENABLED ATTACK VECTORS                             │
  ├─────────────────────────────────────────────────────┤
  │  [RCE]     xp_cmdshell enabled                      │
  │  [RCE]     SQL Agent job 'VulnJob' (sp_start_job)   │
  │  [NTLM]    xp_dirtree / xp_fileexist (PUBLIC)       │
  │  [PRIVESC] $SqlServiceAccount has SeImpersonatePrivilege
  │  [PRIVESC] $SqlServiceAccount has SeAssignPrimaryToken
  │  [INIT]    WinRM open + basic auth (port 5985)      │
  │  [INIT]    Bruteforcable SA (weak password)         │
  │  [CREDS]   VulnDB.dbo.AppCredentials (plaintext)    │
  │  [CREDS]   SA pw == local admin pw (cred reuse)     │
  │  [AUTH]    Mixed mode auth (SQL + Windows)          │
  │  [TODO]    SQL02 linked server (pending SQL02 setup) │
  └─────────────────────────────────────────────────────┘

"@ -ForegroundColor White

Write-Host "  [!] THIS MACHINE IS INTENTIONALLY VULNERABLE. ISOLATE FROM PRODUCTION NETWORKS." -ForegroundColor Red
Write-Host ""