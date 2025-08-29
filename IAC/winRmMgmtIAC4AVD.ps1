<#
.SYNOPSIS
    Configure or remove WinRM over HTTPS with a self-signed certificate.

.DESCRIPTION
    This script enables or removes secure WinRM (Windows Remote Management) 
    on the local machine. It supports two actions:
        -Action Install : 
            * Enables PowerShell remoting
            * Creates/uses a self-signed certificate for the hostname
            * Configures a WinRM HTTPS listener on port 5986
            * Opens firewall rules for WinRM (HTTP/HTTPS)
            * Enables Basic authentication
        -Action Remove :
            * Deletes WinRM HTTPS listeners
            * Removes WinRM firewall rules
            * Disables Basic authentication
            * (Optionally disables PSRemoting if uncommented)

.PARAMETER Action
    Install or Remove (required)

.EXAMPLE
    .\winRmMgmtIAC4AVD.ps1 -Action Install
    Configures WinRM over HTTPS.

.EXAMPLE
    .\winRmMgmtIAC4AVD.ps1 -Action Remove
    Cleans up the WinRM HTTPS configuration.

.NOTES
    Author   : MULTIPHARMA
    Created  : 2025-08-29
    Usage    : Run as Administrator
    Security : Basic authentication should only be used with HTTPS.
               For production, consider using a trusted certificate instead
               of a self-signed one.
#>

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("Install","Remove")]
    [string]$Action
)

# --- Setup Variables ---
$myHost   = hostname
$myDomain = "multi.be"
$myDNSHost = "$myHost.$myDomain"

Write-Host "=== WinRM HTTPS Toggle Script ==="
Write-Host "Action selected: $Action"
Write-Host "Host FQDN: $myDNSHost"

# --- Helper Functions ---
function Ensure-FirewallRule {
    param([string]$Name,[int]$Port)
    if (-not (Get-NetFirewallRule -DisplayName $Name -ErrorAction SilentlyContinue)) {
        Write-Host "Adding firewall rule: $Name (Port $Port)"
        netsh advfirewall firewall add rule name="$Name" dir=in localport=$Port protocol=TCP action=allow
    } else {
        Write-Host "Firewall rule '$Name' already exists. Skipping..."
    }
}

function Remove-FirewallRule {
    param([string]$Name)
    $rule = Get-NetFirewallRule -DisplayName $Name -ErrorAction SilentlyContinue
    if ($rule) {
        Write-Host "Removing firewall rule: $Name"
        Remove-NetFirewallRule -DisplayName $Name
    } else {
        Write-Host "Firewall rule '$Name' not found. Skipping..."
    }
}

# --- Main Logic ---
if ($Action -eq "Install") {
    Write-Host "Starting installation of WinRM over HTTPS..."

    Write-Host "Enabling PowerShell remoting..."
    Enable-PSRemoting -Force

    Write-Host "Checking/adding firewall rules..."
    Ensure-FirewallRule -Name "WinRM-HTTP" -Port 5985
    Ensure-FirewallRule -Name "WinRM-HTTPS" -Port 5986

    Write-Host "Checking for existing self-signed certificate..."
    $cert = Get-ChildItem -Path Cert:\LocalMachine\My |
            Where-Object { $_.Subject -like "*CN=$myDNSHost" } |
            Sort-Object NotAfter -Descending |
            Select-Object -First 1
    if (-not $cert) {
        Write-Host "No certificate found. Creating a new self-signed certificate..."
        $cert = New-SelfSignedCertificate -DnsName $myDNSHost -CertStoreLocation Cert:\LocalMachine\My
    } else {
        Write-Host "Found existing certificate: $($cert.Thumbprint)"
    }
    $thumbprint = $cert.Thumbprint

    Write-Host "Configuring WinRM HTTPS listener..."
    $listener = winrm enumerate winrm/config/Listener | Where-Object { $_ -match "Transport = HTTPS" -and $_ -match $thumbprint }
    if (-not $listener) {
        Write-Host "Listener does not exist. Creating..."
        winrm delete winrm/config/Listener?Address=*+Transport=HTTPS 2>$null
        $listenerSettings = "@{Hostname=`"$myDNSHost`";CertificateThumbprint=`"$thumbprint`"}"
        winrm create winrm/config/Listener?Address=*+Transport=HTTPS $listenerSettings
    } else {
        Write-Host "Listener already configured. Skipping..."
    }

    Write-Host "Enabling Basic authentication..."
    $basicAuth = Get-Item WSMan:\localhost\Service\Auth\Basic
    if (-not $basicAuth.Value) {
        Set-Item WSMan:\localhost\Service\Auth\Basic -Value $true
        Write-Host "Basic authentication enabled."
    } else {
        Write-Host "Basic authentication already enabled. Skipping..."
    }

    Write-Host "=== Installation complete ==="
}

elseif ($Action -eq "Remove") {
    Write-Host "Starting removal of WinRM HTTPS configuration..."

    Write-Host "Checking for existing HTTPS listeners..."
    $httpsListeners = winrm enumerate winrm/config/Listener | Where-Object { $_ -match "Transport = HTTPS" }
    if ($httpsListeners) {
        Write-Host "Removing listener(s)..."
        winrm delete winrm/config/Listener?Address=*+Transport=HTTPS
    } else {
        Write-Host "No listener found. Skipping..."
    }

    Write-Host "Removing firewall rules..."
    Remove-FirewallRule -Name "WinRM-HTTP"
    Remove-FirewallRule -Name "WinRM-HTTPS"

    Write-Host "Disabling Basic authentication..."
    $basicAuth = Get-Item WSMan:\localhost\Service\Auth\Basic
    if ($basicAuth.Value) {
        Set-Item WSMan:\localhost\Service\Auth\Basic -Value $false
        Write-Host "Basic authentication disabled."
    } else {
        Write-Host "Already disabled. Skipping..."
    }

    # Optional: disable PSRemoting completely
    # Write-Host "Disabling PowerShell remoting..."
    # Disable-PSRemoting -Force

    Write-Host "=== Removal complete ==="
}
