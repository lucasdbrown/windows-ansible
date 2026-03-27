# Run this script from an elevated PowerShell session (Administrator).
# It:
# - Creates a local user: ansible / DeployWindows123!
# - Adds that user to Administrators and Remote Management Users
# - Enables PowerShell remoting / WinRM
# - Sets LocalAccountTokenFilterPolicy for local admin remoting
# - Creates a self-signed cert and WinRM HTTPS listener on 5986
# - Opens the firewall for 5986
# - Disables Basic auth and unencrypted WinRM
# - Leaves NTLM/Negotiate enabled

$ErrorActionPreference = "Stop"

function Write-Info($msg) {
    Write-Host "[*] $msg" -ForegroundColor Cyan
}

function Write-Ok($msg) {
    Write-Host "[+] $msg" -ForegroundColor Green
}

function Ensure-Admin {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script must be run as Administrator."
    }
}

function Ensure-LocalUser {
    param(
        [string]$Username,
        [string]$Password
    )

    $existing = Get-LocalUser -Name $Username -ErrorAction SilentlyContinue
    $securePassword = ConvertTo-SecureString $Password -AsPlainText -Force

    if (-not $existing) {
        Write-Info "Creating local user '$Username'..."
        New-LocalUser `
            -Name $Username `
            -Password $securePassword `
            -PasswordNeverExpires `
            -UserMayNotChangePassword `
            -AccountNeverExpires `
            -FullName "Ansible Automation Account" `
            -Description "Local automation account for Ansible" | Out-Null
        Write-Ok "Created local user '$Username'."
    }
    else {
        Write-Info "User '$Username' already exists. Resetting password..."
        $existing | Set-LocalUser -Password $securePassword
        Write-Ok "Password reset for '$Username'."
    }
}

function Ensure-LocalGroupMember {
    param(
        [string]$GroupName,
        [string]$MemberName
    )

    try {
        $members = Get-LocalGroupMember -Group $GroupName -ErrorAction Stop
        $already = $members | Where-Object { $_.Name -like "*\$MemberName" -or $_.Name -eq $MemberName }
        if (-not $already) {
            Write-Info "Adding '$MemberName' to '$GroupName'..."
            Add-LocalGroupMember -Group $GroupName -Member $MemberName -ErrorAction Stop
            Write-Ok "Added '$MemberName' to '$GroupName'."
        }
        else {
            Write-Info "'$MemberName' already in '$GroupName'."
        }
    }
    catch {
        throw "Failed to add '$MemberName' to '$GroupName': $($_.Exception.Message)"
    }
}

function Ensure-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [string]$Type = "DWORD"
    )

    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }

    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
    Write-Ok "Set registry $Path\$Name = $Value"
}

function Ensure-WinRMService {
    Write-Info "Enabling PowerShell remoting..."
    Enable-PSRemoting -Force -SkipNetworkProfileCheck
    Set-Service -Name WinRM -StartupType Automatic
    Start-Service -Name WinRM
    Write-Ok "WinRM service enabled and running."
}

function Ensure-Certificate {
    param(
        [string[]]$DnsNames
    )

    $subjectPrimary = $DnsNames[0]
    Write-Info "Creating self-signed certificate for: $($DnsNames -join ', ')"

    $cert = New-SelfSignedCertificate `
        -CertStoreLocation "Cert:\LocalMachine\My" `
        -DnsName $DnsNames `
        -NotAfter (Get-Date).AddYears(3) `
        -KeyAlgorithm RSA `
        -KeyLength 2048 `
        -HashAlgorithm SHA256 `
        -Provider "Microsoft Software Key Storage Provider" `
        -Subject "CN=$subjectPrimary"

    Write-Ok "Created certificate: $($cert.Thumbprint)"
    return $cert
}

function Ensure-HttpsListener {
    param(
        [string]$Thumbprint
    )

    $listeners = Get-ChildItem -Path WSMan:\localhost\Listener -ErrorAction SilentlyContinue
    $httpsListener = $listeners | Where-Object { $_.Keys -contains "Transport=HTTPS" }

    if (-not $httpsListener) {
        Write-Info "Creating WinRM HTTPS listener on 5986..."
        New-Item `
            -Path WSMan:\localhost\Listener `
            -Address * `
            -Transport HTTPS `
            -Port 5986 `
            -CertificateThumbprint $Thumbprint `
            -Enabled $true `
            -Force | Out-Null
        Write-Ok "Created HTTPS listener."
    }
    else {
        Write-Info "HTTPS listener already exists."
    }
}

function Ensure-FirewallRule {
    $ruleName = "Ansible WinRM HTTPS 5986"

    $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if (-not $existing) {
        Write-Info "Opening Windows Firewall TCP/5986..."
        New-NetFirewallRule `
            -DisplayName $ruleName `
            -Direction Inbound `
            -Action Allow `
            -Protocol TCP `
            -LocalPort 5986 `
            -Profile Any | Out-Null
        Write-Ok "Firewall rule created."
    }
    else {
        Write-Info "Firewall rule already exists."
    }
}

function Configure-WinRMAuth {
    Write-Info "Configuring WinRM authentication and encryption settings..."

    Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $false
    Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $false
    Set-Item -Path WSMan:\localhost\Service\Auth\Kerberos -Value $true
    Set-Item -Path WSMan:\localhost\Service\Auth\Negotiate -Value $true
    Set-Item -Path WSMan:\localhost\Service\Auth\Certificate -Value $false
    Set-Item -Path WSMan:\localhost\Service\Auth\CredSSP -Value $false

    Write-Ok "WinRM auth configured."
}

function Show-Status {
    Write-Host ""
    Write-Host "==== WinRM Listener Status ====" -ForegroundColor Yellow
    winrm enumerate winrm/config/Listener

    Write-Host ""
    Write-Host "==== WinRM Service Auth ====" -ForegroundColor Yellow
    Get-ChildItem WSMan:\localhost\Service\Auth | Format-List

    Write-Host ""
    Write-Host "==== Quick Test ====" -ForegroundColor Yellow
    try {
        Test-WSMan -UseSSL -ComputerName localhost | Out-Host
    }
    catch {
        Write-Warning "Test-WSMan over SSL failed: $($_.Exception.Message)"
    }
}

# Main
Ensure-Admin

$Username = "ansible"
$Password = "DeployWindows123!"

Ensure-LocalUser -Username $Username -Password $Password
Ensure-LocalGroupMember -GroupName "Administrators" -MemberName $Username
Ensure-LocalGroupMember -GroupName "Remote Management Users" -MemberName $Username

Ensure-WinRMService

# Required for local accounts to work properly with elevated remote management
Ensure-RegistryValue `
    -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "LocalAccountTokenFilterPolicy" `
    -Value 1 `
    -Type "DWORD"

$dnsNames = @(
    $env:COMPUTERNAME,
    "$($env:COMPUTERNAME).$($env:USERDNSDOMAIN)"
) | Where-Object { $_ -and $_ -notmatch "^\s*$" } | Select-Object -Unique

if (-not $dnsNames -or $dnsNames.Count -eq 0) {
    $dnsNames = @($env:COMPUTERNAME)
}

$cert = Ensure-Certificate -DnsNames $dnsNames
Ensure-HttpsListener -Thumbprint $cert.Thumbprint
Ensure-FirewallRule
Configure-WinRMAuth

Write-Ok "Bootstrap complete."
Write-Host ""
Write-Host "Use these Ansible variables:" -ForegroundColor Green
Write-Host "  ansible_connection=winrm"
Write-Host "  ansible_winrm_transport=ntlm"
Write-Host "  ansible_winrm_scheme=https"
Write-Host "  ansible_port=5986"
Write-Host "  ansible_winrm_server_cert_validation=ignore"
Write-Host "  ansible_user=ansible"
Write-Host "  ansible_password=DeployWindows123!"
Write-Host ""

Show-Status