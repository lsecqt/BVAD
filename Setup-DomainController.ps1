#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Promotes a Windows Server 2019 to a Domain Controller with DNS and AD-Integrated DNS.

.DESCRIPTION
    This script renames the computer, installs the AD DS and DNS Server roles, then
    promotes the server to a Domain Controller for a new forest. It configures
    AD-Integrated DNS zones automatically as part of the promotion process.

    Intended for LAB / INTENTIONALLY VULNERABLE AD environments only.

.PARAMETER DomainName
    The fully qualified domain name for the new Active Directory forest.
    Example: yourlab.local

.PARAMETER AdminPassword
    The password for the local Administrator account, which becomes the
    Domain Administrator after promotion.

.PARAMETER DSRMPassword
    The Directory Services Restore Mode (Safe Mode) administrator password.
    Used for offline DC recovery.

.PARAMETER Hostname
    The desired computer name / hostname for the Domain Controller.
    Example: DC01

.EXAMPLE
    .\Setup-DomainController.ps1 -DomainName "yourlab.local" -AdminPassword "P@ssw0rd123!" -DSRMPassword "DSRM@dmin1!" -Hostname "DC01"
#>

param(
    [Parameter(Mandatory = $true, HelpMessage = "Fully qualified domain name (e.g. yourlab.local)")]
    [ValidatePattern('^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$')]
    [string]$DomainName,

    [Parameter(Mandatory = $true, HelpMessage = "Password for the local/domain Administrator account")]
    [string]$AdminPassword,

    [Parameter(Mandatory = $true, HelpMessage = "Directory Services Restore Mode (DSRM) password")]
    [string]$DSRMPassword,

    [Parameter(Mandatory = $true, HelpMessage = "Hostname for the Domain Controller (e.g. DC01)")]
    [ValidatePattern('^[a-zA-Z0-9-]{1,15}$')]
    [string]$Hostname
)

# ──────────────────────────────────────────────
# Helper: derive NetBIOS name from domain name
# ──────────────────────────────────────────────
$NetBIOSName = ($DomainName -split '\.')[0].ToUpper()

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "  Domain Controller Setup Script"             -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Domain Name  : $DomainName"                 -ForegroundColor Yellow
Write-Host "  NetBIOS Name : $NetBIOSName"                -ForegroundColor Yellow
Write-Host "  Hostname     : $Hostname"                   -ForegroundColor Yellow
Write-Host ""

# ──────────────────────────────────────────────
# Convert plaintext passwords to SecureStrings
# ──────────────────────────────────────────────
$SecureAdminPassword = ConvertTo-SecureString $AdminPassword -AsPlainText -Force
$SecureDSRMPassword  = ConvertTo-SecureString $DSRMPassword  -AsPlainText -Force

# ──────────────────────────────────────────────
# Step 1: Set the local Administrator password
# ──────────────────────────────────────────────
Write-Host "[1/6] Setting local Administrator password..." -ForegroundColor Green

try {
    $builtinAdmin = Get-LocalUser | Where-Object { $_.SID -like "*-500" }

    if ($builtinAdmin) {
        $builtinAdmin | Set-LocalUser -Password $SecureAdminPassword -ErrorAction Stop
        Write-Host "  [OK] Password set for '$($builtinAdmin.Name)' (built-in Administrator)." -ForegroundColor Gray

        $builtinAdmin | Enable-LocalUser -ErrorAction SilentlyContinue
    } else {
        Write-Host "  [WARN] Could not find built-in Administrator. Skipping password change." -ForegroundColor Yellow
    }
}
catch {
    Write-Host "  [WARN] Failed to set local admin password: $_" -ForegroundColor Yellow
    Write-Host "         The domain admin password may need to be set manually after promotion." -ForegroundColor Yellow
}

# ──────────────────────────────────────────────
# Step 2: Rename the computer
#   - The rename takes effect on the next reboot
#     (which happens after DC promotion in Step 6)
# ──────────────────────────────────────────────
Write-Host "[2/6] Renaming computer to '$Hostname'..." -ForegroundColor Green

$currentName = $env:COMPUTERNAME

if ($currentName -eq $Hostname.ToUpper()) {
    Write-Host "  [OK] Hostname is already '$Hostname'. Skipping." -ForegroundColor Gray
} else {
    try {
        Rename-Computer -NewName $Hostname -Force -ErrorAction Stop
        Write-Host "  [OK] Computer renamed from '$currentName' to '$Hostname' (applies after reboot)." -ForegroundColor Gray
    }
    catch {
        Write-Host "  [FAIL] Failed to rename computer: $_" -ForegroundColor Red
        exit 1
    }
}

# ──────────────────────────────────────────────
# Step 3: Install required Windows features
# ──────────────────────────────────────────────
Write-Host "[3/6] Installing AD DS and DNS Server roles..." -ForegroundColor Green

$features = @(
    "AD-Domain-Services",   # Active Directory Domain Services
    "DNS",                  # DNS Server
    "RSAT-AD-Tools",        # AD management tools
    "RSAT-DNS-Server"       # DNS management tools
)

foreach ($feature in $features) {
    $result = Install-WindowsFeature -Name $feature -IncludeManagementTools -ErrorAction Stop
    if ($result.Success) {
        Write-Host "  [OK] $feature installed." -ForegroundColor Gray
    } else {
        Write-Host "  [FAIL] $feature failed to install." -ForegroundColor Red
        exit 1
    }
}

# ──────────────────────────────────────────────
# Step 4: Import the ADDSDeployment module
# ──────────────────────────────────────────────
Write-Host "[4/6] Importing ADDSDeployment module..." -ForegroundColor Green
Import-Module ADDSDeployment -ErrorAction Stop

# ──────────────────────────────────────────────
# Step 5: Configure DNS client to point to itself
# ──────────────────────────────────────────────
Write-Host "[5/6] Setting DNS client to loopback (127.0.0.1)..." -ForegroundColor Green

$activeNIC = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1

if ($activeNIC) {
    Set-DnsClientServerAddress -InterfaceIndex $activeNIC.ifIndex -ServerAddresses "127.0.0.1" -ErrorAction Stop
    Write-Host "  [OK] DNS set to 127.0.0.1 on '$($activeNIC.Name)'." -ForegroundColor Gray
} else {
    Write-Host "  [WARN] No active NIC found. DNS may need manual configuration." -ForegroundColor Yellow
}

# ──────────────────────────────────────────────
# Step 6: Promote to Domain Controller
#   - Creates a new forest
#   - Installs DNS and configures AD-integrated DNS
#   - Sets forest/domain functional level to Server 2016
#   - The reboot also applies the hostname change
# ──────────────────────────────────────────────
Write-Host "[6/6] Promoting server to Domain Controller..." -ForegroundColor Green
Write-Host "        This will create a NEW FOREST: $DomainName" -ForegroundColor Yellow
Write-Host ""

$params = @{
    DomainName                    = $DomainName
    DomainNetbiosName             = $NetBIOSName
    SafeModeAdministratorPassword = $SecureDSRMPassword

    # Install and configure DNS on this DC
    InstallDns                    = $true

    # Create a DNS delegation (not needed for a lab root domain)
    CreateDnsDelegation           = $false

    # Forest and Domain functional level — Windows Server 2016 (highest for 2019)
    ForestMode                    = "WinThreshold"
    DomainMode                    = "WinThreshold"

    # Database / Log / SYSVOL paths (defaults)
    DatabasePath                  = "C:\Windows\NTDS"
    LogPath                       = "C:\Windows\NTDS"
    SysvolPath                    = "C:\Windows\SYSVOL"

    # Suppress confirmation prompts
    Force                         = $true
    NoRebootOnCompletion          = $false
}

try {
    Install-ADDSForest @params -ErrorAction Stop
}
catch {
    Write-Host "[ERROR] Promotion failed: $_" -ForegroundColor Red
    exit 1
}

# ──────────────────────────────────────────────
# The server will automatically reboot after
# a successful promotion. The hostname change
# from Step 2 also takes effect on this reboot.
#
# After reboot, AD-Integrated DNS is configured:
#   - A forward lookup zone matching the domain
#     is stored in AD (forest-wide DNS app partition)
#   - _msdcs.<DomainName> zone is created
#   - SRV records for DC location are registered
#
# You can verify with:
#   Get-DnsServerZone
#   Get-DnsServerResourceRecord -ZoneName "<DomainName>"
#   Resolve-DnsName -Name "<DomainName>" -Type SOA
#   hostname
# ──────────────────────────────────────────────

Write-Host ""
Write-Host "Server is rebooting to complete DC promotion..." -ForegroundColor Cyan
Write-Host "Hostname '$Hostname' will also take effect after reboot." -ForegroundColor Cyan
Write-Host "After reboot, log in as $NetBIOSName\Administrator" -ForegroundColor Yellow