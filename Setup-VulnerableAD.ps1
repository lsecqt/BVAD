#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Populates an Active Directory lab with intentionally vulnerable configurations.

.DESCRIPTION
    This script creates a vulnerable AD environment for security training and
    penetration testing practice. It configures multiple attack vectors including
    weak passwords, Kerberoastable/ASREProastable accounts, SMB signing disabled,
    LDAP channel binding disabled, NTLM enabled, WebClient, and more.

    !! FOR LAB USE ONLY — NEVER RUN IN PRODUCTION !!

.PARAMETER DomainName
    The FQDN of the existing AD domain (e.g. yourlab.local).

.EXAMPLE
    .\Setup-VulnerableAD.ps1 -DomainName "yourlab.local"
#>

param(
    [Parameter(Mandatory = $true, HelpMessage = "Fully qualified domain name (e.g. yourlab.local)")]
    [string]$DomainName
)

# ──────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────
$TotalUsers              = 400
$PercentUsernameAsPass   = 0.05   # 5%  → 20 users
$PercentEmptyPass        = 0.03   # 3%  → 12 users
$KerberoastableCount     = 15
$ASREPRoastableCount     = 15
$PasswordInDescCount     = 4
$DefaultPassword         = "Welcome2025!"

# ──────────────────────────────────────────────
# Build the domain DN from the FQDN
# ──────────────────────────────────────────────
$DomainDN = ($DomainName -split '\.' | ForEach-Object { "DC=$_" }) -join ','

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "  Vulnerable AD Setup Script"                 -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Domain    : $DomainName"                    -ForegroundColor Yellow
Write-Host "  Domain DN : $DomainDN"                      -ForegroundColor Yellow
Write-Host "  Users     : $TotalUsers"                    -ForegroundColor Yellow
Write-Host ""

Import-Module ActiveDirectory -ErrorAction Stop

# ══════════════════════════════════════════════
# 1. WEAK PASSWORD POLICY
# ══════════════════════════════════════════════
Write-Host "[1/12] Configuring weak password policy..." -ForegroundColor Green

# Minimum 8 chars, no complexity, no lockout, max password age 0 (never expires)
Set-ADDefaultDomainPasswordPolicy -Identity $DomainName `
    -MinPasswordLength 8 `
    -ComplexityEnabled $false `
    -PasswordHistoryCount 0 `
    -MinPasswordAge  "0.00:00:00" `
    -MaxPasswordAge  "0.00:00:00" `
    -LockoutThreshold 0 `
    -LockoutDuration "0.00:00:00" `
    -LockoutObservationWindow "0.00:00:00" `
    -ReversibleEncryptionEnabled $false `
    -ErrorAction Stop

Write-Host "  [OK] Min 8 chars, no complexity, no lockout, passwords never expire." -ForegroundColor Gray

# Force the policy to apply immediately before creating users
Write-Host "  [..] Applying policy update (gpupdate)..." -ForegroundColor DarkGray
gpupdate /force 2>&1 | Out-Null
Start-Sleep -Seconds 5
Write-Host "  [OK] Policy applied and waiting for propagation." -ForegroundColor Gray

# ══════════════════════════════════════════════
# 2. CREATE ORGANIZATIONAL UNITS
# ══════════════════════════════════════════════
Write-Host "[2/12] Creating Organizational Units..." -ForegroundColor Green

$OUs = @("IT", "HR", "Finance", "Sales", "Marketing", "Engineering", "Legal", "Operations", "Executive", "Support")

foreach ($ou in $OUs) {
    try {
        New-ADOrganizationalUnit -Name $ou -Path $DomainDN -ProtectedFromAccidentalDeletion $false -ErrorAction Stop
        Write-Host "  [OK] OU=$ou created." -ForegroundColor Gray
    }
    catch [Microsoft.ActiveDirectory.Management.ADException] {
        Write-Host "  [SKIP] OU=$ou already exists." -ForegroundColor DarkGray
    }
}

# ══════════════════════════════════════════════
# 3. GENERATE 400 USERS
# ══════════════════════════════════════════════
Write-Host "[3/12] Creating $TotalUsers user accounts..." -ForegroundColor Green

# --- Name pools ---
$FirstNames = @(
    "James","Mary","Robert","Patricia","John","Jennifer","Michael","Linda","David","Elizabeth",
    "William","Barbara","Richard","Susan","Joseph","Jessica","Thomas","Sarah","Christopher","Karen",
    "Charles","Lisa","Daniel","Nancy","Matthew","Betty","Anthony","Margaret","Mark","Sandra",
    "Donald","Ashley","Steven","Kimberly","Paul","Emily","Andrew","Donna","Joshua","Michelle",
    "Kenneth","Carol","Kevin","Amanda","Brian","Dorothy","George","Melissa","Timothy","Deborah",
    "Ronald","Stephanie","Edward","Rebecca","Jason","Sharon","Jeffrey","Laura","Ryan","Cynthia",
    "Jacob","Kathleen","Gary","Amy","Nicholas","Angela","Eric","Shirley","Jonathan","Anna",
    "Stephen","Brenda","Larry","Pamela","Justin","Emma","Scott","Nicole","Brandon","Helen",
    "Benjamin","Samantha","Samuel","Katherine","Raymond","Christine","Gregory","Debra","Frank","Rachel",
    "Alexander","Carolyn","Patrick","Janet","Jack","Catherine","Dennis","Maria","Jerry","Heather",
    "Tyler","Diane","Aaron","Ruth","Jose","Julie","Adam","Olivia","Nathan","Joyce",
    "Henry","Virginia","Douglas","Victoria","Zachary","Kelly","Peter","Lauren","Kyle","Christina",
    "Noah","Joan","Ethan","Evelyn","Jeremy","Judith","Walter","Megan","Christian","Andrea",
    "Keith","Cheryl","Roger","Hannah","Terry","Jacqueline","Austin","Martha","Sean","Gloria",
    "Gerald","Teresa","Carl","Ann","Harold","Sara","Dylan","Madison","Arthur","Frances",
    "Lawrence","Kathryn","Jordan","Janice","Jesse","Jean","Bryan","Abigail","Billy","Alice",
    "Bruce","Judy","Gabriel","Sophia","Joe","Grace","Logan","Denise","Albert","Amber",
    "Willie","Doris","Alan","Marilyn","Eugene","Danielle","Russell","Beverly","Elijah","Isabella",
    "Randy","Theresa","Philip","Diana","Harry","Natalie","Vincent","Brittany","Bobby","Charlotte",
    "Johnny","Marie","Bradley","Kayla","Roy","Alexis","Martin","Lori","Clarence","Marie"
)

$LastNames = @(
    "Smith","Johnson","Williams","Brown","Jones","Garcia","Miller","Davis","Rodriguez","Martinez",
    "Hernandez","Lopez","Gonzalez","Wilson","Anderson","Thomas","Taylor","Moore","Jackson","Martin",
    "Lee","Perez","Thompson","White","Harris","Sanchez","Clark","Ramirez","Lewis","Robinson",
    "Walker","Young","Allen","King","Wright","Scott","Torres","Nguyen","Hill","Flores",
    "Green","Adams","Nelson","Baker","Hall","Rivera","Campbell","Mitchell","Carter","Roberts",
    "Gomez","Phillips","Evans","Turner","Diaz","Parker","Cruz","Edwards","Collins","Reyes",
    "Stewart","Morris","Morales","Murphy","Cook","Rogers","Gutierrez","Ortiz","Morgan","Cooper",
    "Peterson","Bailey","Reed","Kelly","Howard","Ramos","Kim","Cox","Ward","Richardson",
    "Watson","Brooks","Chavez","Wood","James","Bennett","Gray","Mendoza","Ruiz","Hughes",
    "Price","Alvarez","Castillo","Sanders","Patel","Myers","Long","Ross","Foster","Jimenez"
)

# --- Build unique user list ---
$users = @()
$usedNames = @{}

for ($i = 1; $i -le $TotalUsers; $i++) {
    $first = $FirstNames[(Get-Random -Minimum 0 -Maximum $FirstNames.Count)]
    $last  = $LastNames[(Get-Random -Minimum 0 -Maximum $LastNames.Count)]

    # Build SAM: first initial + last name (lowercase), append number if duplicate
    $baseSam = ($first[0] + $last).ToLower()
    $sam = $baseSam
    $counter = 1

    while ($usedNames.ContainsKey($sam)) {
        $sam = "$baseSam$counter"
        $counter++
    }

    $usedNames[$sam] = $true
    $users += [PSCustomObject]@{
        FirstName = $first
        LastName  = $last
        SAM       = $sam
        OU        = $OUs[(Get-Random -Minimum 0 -Maximum $OUs.Count)]
    }
}

# --- Determine special user indices ---
$indices = 0..($TotalUsers - 1) | Sort-Object { Get-Random }
$pointer = 0

$usernameAsPassCount = [math]::Floor($TotalUsers * $PercentUsernameAsPass)   # 20
$emptyPassCount      = [math]::Floor($TotalUsers * $PercentEmptyPass)         # 12

$usernameAsPassIdx   = $indices[$pointer..($pointer + $usernameAsPassCount - 1)]; $pointer += $usernameAsPassCount
$emptyPassIdx        = $indices[$pointer..($pointer + $emptyPassCount - 1)];      $pointer += $emptyPassCount
$kerberoastIdx       = $indices[$pointer..($pointer + $KerberoastableCount - 1)]; $pointer += $KerberoastableCount
$asrepIdx            = $indices[$pointer..($pointer + $ASREPRoastableCount - 1)]; $pointer += $ASREPRoastableCount
$passInDescIdx       = $indices[$pointer..($pointer + $PasswordInDescCount - 1)]; $pointer += $PasswordInDescCount

# --- Fake SPNs for Kerberoastable users ---
$SPNServices = @(
    "MSSQLSvc","HTTP","CIFS","HOST","exchangeMDB","kadmin","ldap","DNS",
    "FIMService","SAPService","vmware","oracle","postgres","iis","kafka"
)

# --- Create the accounts ---
$createdCount = 0
$descPasswords = @("Summer2025!", "Passw0rd!", "Company123!", "Welcome1!")

for ($i = 0; $i -lt $TotalUsers; $i++) {
    $u   = $users[$i]
    $upn = "$($u.SAM)@$DomainName"
    $ouPath = "OU=$($u.OU),$DomainDN"
    $displayName = "$($u.FirstName) $($u.LastName)"

    # Determine password
    $description = "Employee - $($u.OU) Department"

    if ($i -in $emptyPassIdx) {
        # Empty password — we set a dummy first, then clear it
        $password = $DefaultPassword
        $clearPassword = $true
    }
    elseif ($i -in $usernameAsPassIdx) {
        # Username = password (pad to 8 chars if needed)
        $rawPass = $u.SAM
        if ($rawPass.Length -lt 8) { $rawPass = $rawPass + ("1" * (8 - $rawPass.Length)) }
        $password = $rawPass
        $clearPassword = $false
    }
    elseif ($i -in $passInDescIdx) {
        # Password stored in description field
        $descPw = $descPasswords[$passInDescIdx.IndexOf($i) % $descPasswords.Count]
        $password = $descPw
        $description = "interal account - Reset password: $descPw"
        $clearPassword = $false
    }
    else {
        $password = $DefaultPassword
        $clearPassword = $false
    }

    try {
        $secPass = ConvertTo-SecureString $password -AsPlainText -Force

        New-ADUser `
            -Name $displayName `
            -GivenName $u.FirstName `
            -Surname $u.LastName `
            -SamAccountName $u.SAM `
            -UserPrincipalName $upn `
            -Path $ouPath `
            -AccountPassword $secPass `
            -Enabled $true `
            -PasswordNeverExpires $true `
            -CannotChangePassword $false `
            -Description $description `
            -ErrorAction Stop

        # ── Empty password: clear it after creation ──
        if ($clearPassword) {
            Set-ADAccountPassword -Identity $u.SAM -Reset -NewPassword (New-Object System.Security.SecureString) -ErrorAction Stop
            Set-ADUser -Identity $u.SAM -PasswordNotRequired $true -ErrorAction Stop
        }

        # ── Kerberoastable: set an SPN ──
        if ($i -in $kerberoastIdx) {
            $svcName = $SPNServices[(Get-Random -Minimum 0 -Maximum $SPNServices.Count)]
            $fakeHost = "$($u.SAM)-srv.$DomainName"
            $spn = "$svcName/$fakeHost"
            Set-ADUser -Identity $u.SAM -ServicePrincipalNames @{Add=$spn} -ErrorAction Stop
        }

        # ── ASREProastable: disable Kerberos pre-auth ──
        if ($i -in $asrepIdx) {
            Set-ADAccountControl -Identity $u.SAM -DoesNotRequirePreAuth $true -ErrorAction Stop
        }

        $createdCount++
    }
    catch {
        Write-Host "  [WARN] Failed to create $($u.SAM): $_" -ForegroundColor Yellow
    }
}

Write-Host "  [OK] Created $createdCount / $TotalUsers users." -ForegroundColor Gray
Write-Host "       - $usernameAsPassCount users with username = password" -ForegroundColor DarkGray
Write-Host "       - $emptyPassCount users with empty passwords" -ForegroundColor DarkGray
Write-Host "       - $KerberoastableCount Kerberoastable users (SPNs set)" -ForegroundColor DarkGray
Write-Host "       - $ASREPRoastableCount ASREProastable users (pre-auth disabled)" -ForegroundColor DarkGray
Write-Host "       - $PasswordInDescCount users with password in description" -ForegroundColor DarkGray

# ══════════════════════════════════════════════
# 4. CREATE SOME GROUPS AND NEST USERS
# ══════════════════════════════════════════════
Write-Host "[4/12] Creating groups and adding members..." -ForegroundColor Green

$groups = @(
    @{ Name = "IT-Admins";       OU = "IT" },
    @{ Name = "HR-Team";         OU = "HR" },
    @{ Name = "Finance-Team";    OU = "Finance" },
    @{ Name = "Helpdesk";        OU = "Support" },
    @{ Name = "Developers";      OU = "Engineering" },
    @{ Name = "Managers";        OU = "Executive" },
    @{ Name = "VPN-Users";       OU = "IT" },
    @{ Name = "SQL-Admins";      OU = "IT" },
    @{ Name = "Backup-Operators"; OU = "Operations" },
    @{ Name = "Sales-Team";      OU = "Sales" }
)

foreach ($g in $groups) {
    $groupPath = "OU=$($g.OU),$DomainDN"
    try {
        New-ADGroup -Name $g.Name -GroupScope Global -GroupCategory Security -Path $groupPath -ErrorAction Stop
        # Add random members from matching OU
        $ouMembers = $users | Where-Object { $_.OU -eq $g.OU } | Get-Random -Count ([math]::Min(15, ($users | Where-Object { $_.OU -eq $g.OU }).Count)) -ErrorAction SilentlyContinue
        foreach ($m in $ouMembers) {
            Add-ADGroupMember -Identity $g.Name -Members $m.SAM -ErrorAction SilentlyContinue
        }
        Write-Host "  [OK] Group '$($g.Name)' created with members." -ForegroundColor Gray
    }
    catch [Microsoft.ActiveDirectory.Management.ADException] {
        Write-Host "  [SKIP] Group '$($g.Name)' already exists." -ForegroundColor DarkGray
    }
}

# ══════════════════════════════════════════════
# 5. SMB SIGNING — DISABLED
# ══════════════════════════════════════════════
Write-Host "[5/12] Disabling SMB signing (DC + Default Domain GPO)..." -ForegroundColor Green

# --- Local registry (this DC) ---
# Server: do not require signing
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" `
    -Name "RequireSecuritySignature" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" `
    -Name "EnableSecuritySignature" -Value 0 -Type DWord -Force

# Client: do not require signing
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
    -Name "RequireSecuritySignature" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
    -Name "EnableSecuritySignature" -Value 0 -Type DWord -Force

Write-Host "  [OK] SMB signing disabled on this DC (registry)." -ForegroundColor Gray

# --- Default Domain Policy GPO (propagates to all domain-joined systems) ---
try {
    $GPOName = "Default Domain Policy"
    $smb_inf = @"

[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Registry Values]
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature=4,0
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature=4,0
MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature=4,0
MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature=4,0
"@

    # Get the GPO ID for Default Domain Policy
    $gpo = Get-GPO -Name $GPOName -ErrorAction Stop
    $gpoId = $gpo.Id.ToString("B").ToUpper()
    $sysvolPath = "C:\Windows\SYSVOL\sysvol\$DomainName\Policies\$gpoId\Machine\Microsoft\Windows NT\SecEdit"

    if (!(Test-Path $sysvolPath)) {
        New-Item -Path $sysvolPath -ItemType Directory -Force | Out-Null
    }

    $existingInf = "$sysvolPath\GptTmpl.inf"

    if (Test-Path $existingInf) {
        # Append SMB settings to existing file if not already present
        $content = Get-Content $existingInf -Raw
        if ($content -notmatch "LanManServer") {
            Add-Content -Path $existingInf -Value $smb_inf.Trim()
        }
    } else {
        Set-Content -Path $existingInf -Value $smb_inf.Trim()
    }

    # Increment GPO version in gpt.ini (SYSVOL) and AD to force replication
    $gptIniPath = "C:\Windows\SYSVOL\sysvol\$DomainName\Policies\$gpoId\gpt.ini"
    if (Test-Path $gptIniPath) {
        $gptContent = Get-Content $gptIniPath -Raw
        if ($gptContent -match 'Version=(\d+)') {
            $currentVer = [int]$Matches[1]
            # Computer portion is the upper 16 bits; increment by 65536
            $newVer = $currentVer + 65536
            $gptContent = $gptContent -replace "Version=\d+", "Version=$newVer"
            Set-Content -Path $gptIniPath -Value $gptContent -Force
        }
    }

    # Also update versionNumber in AD
    $gpoDN = "CN=$gpoId,CN=Policies,CN=System,$DomainDN"
    try {
        $gpoAD = [ADSI]"LDAP://$gpoDN"
        $gpoAD.Properties["versionNumber"].Value = $newVer
        $gpoAD.CommitChanges()
    } catch {
        Write-Host "  [WARN] Could not update GPO version in AD: $_" -ForegroundColor Yellow
    }

    Write-Host "  [OK] SMB signing disabled in Default Domain Policy GPO." -ForegroundColor Gray
}
catch {
    Write-Host "  [WARN] Could not update GPO for SMB signing: $_" -ForegroundColor Yellow
    Write-Host "         SMB signing is still disabled locally on this DC." -ForegroundColor Yellow
}

# ══════════════════════════════════════════════
# 6. LDAP CHANNEL BINDING — DISABLED
# ══════════════════════════════════════════════
Write-Host "[6/12] Disabling LDAP channel binding and signing..." -ForegroundColor Green

# LDAP channel binding: 0 = Never
$ldapPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
if (!(Test-Path $ldapPath)) { New-Item -Path $ldapPath -Force | Out-Null }
Set-ItemProperty -Path $ldapPath -Name "LdapEnforceChannelBinding" -Value 0 -Type DWord -Force

# LDAP server signing requirement: 0 = None
Set-ItemProperty -Path $ldapPath -Name "LDAPServerIntegrity" -Value 0 -Type DWord -Force

# LDAP client signing: 0 = Not required
$ldapClientPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP"
if (!(Test-Path $ldapClientPath)) { New-Item -Path $ldapClientPath -Force | Out-Null }
Set-ItemProperty -Path $ldapClientPath -Name "LDAPClientIntegrity" -Value 0 -Type DWord -Force

Write-Host "  [OK] LDAP channel binding = Never, LDAP signing = None." -ForegroundColor Gray

# ══════════════════════════════════════════════
# 7. ENABLE WEBCLIENT SERVICE
# ══════════════════════════════════════════════
Write-Host "[7/12] Installing and enabling WebClient service..." -ForegroundColor Green

try {
    # Install WebDAV feature (required on Server OS)
    Install-WindowsFeature WebDAV-Redirector -ErrorAction SilentlyContinue | Out-Null

    Set-Service -Name WebClient -StartupType Automatic -ErrorAction Stop
    Start-Service -Name WebClient -ErrorAction Stop
    Write-Host "  [OK] WebClient service installed, set to Automatic, and started." -ForegroundColor Gray
}
catch {
    Write-Host "  [WARN] WebClient setup issue: $_" -ForegroundColor Yellow
    Write-Host "         You may need to install 'WebDAV-Redirector' feature manually." -ForegroundColor Yellow
}

# ══════════════════════════════════════════════
# 8. NTLM AUTHENTICATION — ENABLED (no restrictions)
# ══════════════════════════════════════════════
Write-Host "[8/12] Ensuring NTLM authentication is fully enabled..." -ForegroundColor Green

$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

# LmCompatibilityLevel: 0 = Send LM & NTLM responses (most permissive)
Set-ItemProperty -Path $lsaPath -Name "LmCompatibilityLevel" -Value 0 -Type DWord -Force

# Unrestrict NTLM: 0 = Allow all
$mspPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
if (!(Test-Path $mspPath)) { New-Item -Path $mspPath -Force | Out-Null }
Set-ItemProperty -Path $mspPath -Name "RestrictReceivingNTLMTraffic" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $mspPath -Name "RestrictSendingNTLMTraffic" -Value 0 -Type DWord -Force

# No NTLM audit-only or blocking
Set-ItemProperty -Path $mspPath -Name "AuditReceivingNTLMTraffic" -Value 0 -Type DWord -Force

Write-Host "  [OK] LmCompatibilityLevel = 0 (LM & NTLM), no NTLM restrictions." -ForegroundColor Gray

# ══════════════════════════════════════════════
# 9. MACHINE ACCOUNT QUOTA (MAQ) = 100
# ══════════════════════════════════════════════
Write-Host "[9/12] Setting ms-DS-MachineAccountQuota to 100..." -ForegroundColor Green

try {
    Set-ADDomain -Identity $DomainName -Replace @{"ms-DS-MachineAccountQuota" = 100} -ErrorAction Stop
    Write-Host "  [OK] MAQ set to 100 (any domain user can join up to 100 machines)." -ForegroundColor Gray
}
catch {
    Write-Host "  [WARN] Failed to set MAQ: $_" -ForegroundColor Yellow
}

# ══════════════════════════════════════════════
# 10. CREATE SERVICE / ADMIN ACCOUNTS (honeypots)
# ══════════════════════════════════════════════
Write-Host "[10/12] Creating service and admin-like accounts..." -ForegroundColor Green

$serviceAccounts = @(
    @{ Name = "svc_sql";     SPN = "MSSQLSvc/sql01.$DomainName`:1433"; Desc = "SQL Service Account" },
    @{ Name = "svc_iis";     SPN = "HTTP/web01.$DomainName";           Desc = "IIS Service Account" },
    @{ Name = "svc_backup";  SPN = "HOST/backup01.$DomainName";        Desc = "Backup Service Account" },
    @{ Name = "svc_exchange"; SPN = "exchangeMDB/mail01.$DomainName";  Desc = "Exchange Service Account" },
    @{ Name = "svc_admin";   SPN = "kadmin/admin01.$DomainName";       Desc = "Admin tool svc - pass: Admin12345!" }
)

foreach ($svc in $serviceAccounts) {
    try {
        $secPass = ConvertTo-SecureString $DefaultPassword -AsPlainText -Force
        New-ADUser `
            -Name $svc.Name `
            -SamAccountName $svc.Name `
            -UserPrincipalName "$($svc.Name)@$DomainName" `
            -Path "OU=IT,$DomainDN" `
            -AccountPassword $secPass `
            -Enabled $true `
            -PasswordNeverExpires $true `
            -Description $svc.Desc `
            -ServicePrincipalNames @($svc.SPN) `
            -ErrorAction Stop

        Write-Host "  [OK] $($svc.Name) created with SPN: $($svc.SPN)" -ForegroundColor Gray
    }
    catch [Microsoft.ActiveDirectory.Management.ADException] {
        Write-Host "  [SKIP] $($svc.Name) already exists." -ForegroundColor DarkGray
    }
}

# ══════════════════════════════════════════════
# 11. DOMAIN ADMINS WITH WEAK PASSWORDS
# ══════════════════════════════════════════════
Write-Host "[11/12] Creating Domain Admin accounts with weak passwords..." -ForegroundColor Green

$domainAdmins = @(
    @{ SAM = "da_admin";    First = "Admin";    Last = "Root";      Pass = "Admin123!" },
    @{ SAM = "da_scott";    First = "Scott";    Last = "Parker";    Pass = "Password1" },
    @{ SAM = "da_jenny";    First = "Jenny";    Last = "Clark";     Pass = "Welcome1!" },
    @{ SAM = "da_mike";     First = "Mike";     Last = "Thompson";  Pass = "Changeme1" },
    @{ SAM = "da_backup";   First = "Backup";   Last = "Admin";     Pass = "Backup2025" },
    @{ SAM = "da_helpdesk"; First = "Helpdesk"; Last = "Admin";     Pass = "Helpdesk1" },
    @{ SAM = "da_sql";      First = "SQL";      Last = "Admin";     Pass = "SQLAdmin1" },
    @{ SAM = "da_rachel";   First = "Rachel";   Last = "Green";     Pass = "Spring2025" },
    @{ SAM = "da_john";     First = "John";     Last = "Mitchell";  Pass = "P@ssw0rd!" },
    @{ SAM = "da_tier0";    First = "Tier0";    Last = "Service";   Pass = "Tier0Svc!" }
)

$daCreated = 0

foreach ($da in $domainAdmins) {
    try {
        $secPass = ConvertTo-SecureString $da.Pass -AsPlainText -Force
        New-ADUser `
            -Name "$($da.First) $($da.Last)" `
            -GivenName $da.First `
            -Surname $da.Last `
            -SamAccountName $da.SAM `
            -UserPrincipalName "$($da.SAM)@$DomainName" `
            -Path "OU=IT,$DomainDN" `
            -AccountPassword $secPass `
            -Enabled $true `
            -PasswordNeverExpires $true `
            -Description "Domain Administrator" `
            -ErrorAction Stop

        # Add to Domain Admins group
        Add-ADGroupMember -Identity "Domain Admins" -Members $da.SAM -ErrorAction Stop

        $daCreated++
        Write-Host "  [OK] $($da.SAM) added to Domain Admins (pass: $($da.Pass))" -ForegroundColor Gray
    }
    catch [Microsoft.ActiveDirectory.Management.ADException] {
        Write-Host "  [SKIP] $($da.SAM) already exists." -ForegroundColor DarkGray
    }
    catch {
        Write-Host "  [WARN] Failed to create $($da.SAM): $_" -ForegroundColor Yellow
    }
}

Write-Host "  [OK] $daCreated Domain Admin accounts created." -ForegroundColor Gray

# ══════════════════════════════════════════════
# 12. FORCE GROUP POLICY UPDATE
# ══════════════════════════════════════════════
Write-Host "[12/12] Forcing Group Policy update..." -ForegroundColor Green

gpupdate /force 2>&1 | Out-Null

Write-Host "  [OK] Group Policy updated." -ForegroundColor Gray

# ══════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════
Write-Host "" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "  VULNERABLE AD SETUP COMPLETE"               -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Attack Surface Summary:" -ForegroundColor Yellow
Write-Host "  ────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host "  [Users]       $TotalUsers accounts across $($OUs.Count) OUs" -ForegroundColor White
Write-Host "  [PassPolicy]  Min 8 chars, no complexity, no lockout" -ForegroundColor White
Write-Host "  [Kerberoast]  $KerberoastableCount users + $($serviceAccounts.Count) svc accounts with SPNs" -ForegroundColor White
Write-Host "  [ASREPRoast]  $ASREPRoastableCount users with pre-auth disabled" -ForegroundColor White
Write-Host "  [User=Pass]   $usernameAsPassCount users (username = password)" -ForegroundColor White
Write-Host "  [EmptyPass]   $emptyPassCount users with empty passwords" -ForegroundColor White
Write-Host "  [PassInDesc]  $PasswordInDescCount users with password in description" -ForegroundColor White
Write-Host "  [SMB Signing] Disabled (DC + Default Domain Policy)" -ForegroundColor White
Write-Host "  [LDAP]        Channel binding = Never, Signing = None" -ForegroundColor White
Write-Host "  [WebClient]   Enabled and running (WebDAV relay attacks)" -ForegroundColor White
Write-Host "  [NTLM]        LmCompatibilityLevel = 0 (LM + NTLM enabled)" -ForegroundColor White
Write-Host "  [MAQ]         ms-DS-MachineAccountQuota = 100" -ForegroundColor White
Write-Host "  [DomAdmins]   10 Domain Admins with weak passwords" -ForegroundColor White
Write-Host ""
Write-Host "  Enumeration commands to verify:" -ForegroundColor Yellow
Write-Host "    Get-ADUser -Filter * | Measure-Object" -ForegroundColor DarkGray
Write-Host "    Get-ADUser -Filter {ServicePrincipalName -ne `"`$null`"} -Properties ServicePrincipalName" -ForegroundColor DarkGray
Write-Host "    Get-ADUser -Filter {DoesNotRequirePreAuth -eq `$true}" -ForegroundColor DarkGray
Write-Host "    Get-ADUser -Filter * -Properties Description | Where { `$_.Description -like '*pass*' }" -ForegroundColor DarkGray
Write-Host "    Get-ADGroupMember -Identity 'Domain Admins'" -ForegroundColor DarkGray
Write-Host "    (Get-ADDomain).ms-DS-MachineAccountQuota" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  !! THIS ENVIRONMENT IS INTENTIONALLY VULNERABLE !!" -ForegroundColor Red
Write-Host "  !! DO NOT EXPOSE TO PRODUCTION NETWORKS          !!" -ForegroundColor Red
Write-Host ""

# A reboot is recommended for all registry changes to take full effect
Write-Host "  A REBOOT is recommended for all changes to take full effect." -ForegroundColor Yellow
Write-Host "  Run: Restart-Computer -Force" -ForegroundColor Yellow
Write-Host ""