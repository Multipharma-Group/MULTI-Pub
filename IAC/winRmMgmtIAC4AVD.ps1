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
    Created  : 2025-08-28
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

$myHost   = hostname
$myDomain = "multi.be"
$myDNSHost = "$myHost.$myDomain"

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

if ($Action -eq "Install") {
    Write-Host "=== Installing WinRM HTTPS configuration ==="

    # Enable PS Remoting
    Enable-PSRemoting -Force

    # Ensure firewall rules
    Ensure-FirewallRule -Name "WinRM-HTTP" -Port 5985
    Ensure-FirewallRule -Name "WinRM-HTTPS" -Port 5986

    # Check for existing cert
    $cert = Get-ChildItem -Path Cert:\LocalMachine\My |
            Where-Object { $_.Subject -like "*CN=$myDNSHost" } |
            Sort-Object NotAfter -Descending |
            Select-Object -First 1

    if (-not $cert) {
        Write-Host "Creating self-signed certificate for $myDNSHost..."
        $cert = New-SelfSignedCertificate -DnsName $myDNSHost -CertStoreLocation Cert:\LocalMachine\My
    } else {
        Write-Host "Using existing certificate $($cert.Thumbprint) for $myDNSHost."
    }

    $thumbprint = $cert.Thumbprint

    # Configure HTTPS listener
    $listener = winrm enumerate winrm/config/Listener | Where-Object { $_ -match "Transport = HTTPS" -and $_ -match $thumbprint }
    if (-not $listener) {
        Write-Host "Configuring WinRM HTTPS listener..."
        winrm delete winrm/config/Listener?Address=*+Transport=HTTPS 2>$null
        $listenerSettings = "@{Hostname=`"$myDNSHost`";CertificateThumbprint=`"$thumbprint`"}"
        winrm create winrm/config/Listener?Address=*+Transport=HTTPS $listenerSettings
    } else {
        Write-Host "WinRM HTTPS listener already configured. Skipping..."
    }

    # Enable Basic Auth
    $basicAuth = Get-Item WSMan:\localhost\Service\Auth\Basic
    if (-not $basicAuth.Value) {
        Write-Host "Enabling Basic authentication..."
        Set-Item WSMan:\localhost\Service\Auth\Basic -Value $true
    } else {
        Write-Host "Basic authentication already enabled. Skipping..."
    }

    Write-Host "=== Installation complete ==="
}

elseif ($Action -eq "Remove") {
    Write-Host "=== Removing WinRM HTTPS configuration ==="

    # Remove listener
    $httpsListeners = winrm enumerate winrm/config/Listener | Where-Object { $_ -match "Transport = HTTPS" }
    if ($httpsListeners) {
        Write-Host "Removing WinRM HTTPS listener(s)..."
        winrm delete winrm/config/Listener?Address=*+Transport=HTTPS
    } else {
        Write-Host "No WinRM HTTPS listener found. Skipping..."
    }

    # Remove firewall rules
    Remove-FirewallRule -Name "WinRM-HTTP"
    Remove-FirewallRule -Name "WinRM-HTTPS"

    # Disable Basic Auth
    $basicAuth = Get-Item WSMan:\localhost\Service\Auth\Basic
    if ($basicAuth.Value) {
        Write-Host "Disabling Basic authentication..."
        Set-Item WSMan:\localhost\Service\Auth\Basic -Value $false
    } else {
        Write-Host "Basic authentication already disabled. Skipping..."
    }

    # (Optional) disable PSRemoting fully
    # Disable-PSRemoting -Force

    Write-Host "=== Removal complete ==="
}
