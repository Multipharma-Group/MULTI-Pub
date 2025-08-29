<#
.SYNOPSIS
  Configure or remove a WinRM HTTPS listener with firewall rules and Basic authentication.

.DESCRIPTION
  This script sets up or removes a WinRM HTTPS listener with a self-signed certificate,
  configures firewall rules, and enables Basic authentication if requested.
  It is designed to run once during first boot or provisioning of an Azure Virtual Desktop VM.

.AUTHOR
  MULTIPHARMA
#>

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Install","Remove")]
    [string]$Action
)

# --- Setup paths ---
$ScriptName     = Split-Path -Path $PSCommandPath -Leaf
$ScriptBaseName = [IO.Path]::GetFileNameWithoutExtension($ScriptName)
$logDir         = "C:\Scripts"
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }

$logFile        = Join-Path $logDir "$ScriptBaseName.log"
$installMarker  = Join-Path $logDir "WinRM-Toggle.installed"
$removeMarker   = Join-Path $logDir "WinRM-Toggle.removed"

Start-Transcript -Path $logFile -Append
Write-Host "===== Running $ScriptName with Action=$Action ====="
Write-Host "Logging to: $logFile"

# --- Safeguard: ensure Action is valid ---
if (-not $Action) {
    Write-Error "No -Action parameter supplied (Install or Remove required)"
    Stop-Transcript
    exit 1
}

# --- Prevent rerun if markers exist ---
if ($Action -eq "Install" -and Test-Path $installMarker) {
    Write-Host "Install action already executed. Exiting."
    Stop-Transcript
    exit 0
}
if ($Action -eq "Remove" -and Test-Path $removeMarker) {
    Write-Host "Remove action already executed. Exiting."
    Stop-Transcript
    exit 0
}

# --- Functions ---
function Enable-WinRmHttps {
    Write-Host "Enabling WinRM HTTPS listener..."

    # Enable WinRM service
    Enable-PSRemoting -Force

    # Firewall rules
    netsh advfirewall firewall add rule name="WinRM-HTTP"  dir=in localport=5985 protocol=TCP action=allow | Out-Null
    netsh advfirewall firewall add rule name="WinRM-HTTPS" dir=in localport=5986 protocol=TCP action=allow | Out-Null

    # Prepare cert
    $myHost    = hostname
    $myDomain  = "multi.be"
    $myDNSHost = "$myHost.$myDomain"

    Write-Host "Creating self-signed cert for $myDNSHost..."
    $cert       = New-SelfSignedCertificate -DnsName $myDNSHost -CertStoreLocation Cert:\LocalMachine\My
    $thumbprint = $cert.Thumbprint

    # Clean existing HTTPS listener
    try {
        Write-Host "Removing existing HTTPS listener if any..."
        winrm delete winrm/config/Listener?Address=*+Transport=HTTPS | Out-Null
    } catch {
        Write-Host "No existing HTTPS listener found, continuing..."
    }

    # Create HTTPS listener
    $listener = "@{Hostname=`"$myDNSHost`";CertificateThumbprint=`"$thumbprint`"}"
    Write-Host "Creating new HTTPS listener..."
    winrm create winrm/config/Listener?Address=*+Transport=HTTPS $listener | Out-Null

    # Enable Basic authentication
    Write-Host "Enabling Basic authentication..."
    Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $true
    Restart-Service WinRM -Force
    $current = (Get-Item WSMan:\localhost\Service\Auth\Basic).Value
    Write-Host "Basic authentication is now set to: $current"

    New-Item -ItemType File -Path $installMarker -Force | Out-Null
    Write-Host "Install marker created: $installMarker"
}

function Disable-WinRmHttps {
    Write-Host "Removing WinRM HTTPS listener..."

    try {
        winrm delete winrm/config/Listener?Address=*+Transport=HTTPS | Out-Null
    } catch {
        Write-Host "No HTTPS listener found to remove."
    }

    # Disable Basic authentication
    Write-Host "Disabling Basic authentication..."
    Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $false
    Restart-Service WinRM -Force
    $current = (Get-Item WSMan:\localhost\Service\Auth\Basic).Value
    Write-Host "Basic authentication is now set to: $current"

    New-Item -ItemType File -Path $removeMarker -Force | Out-Null
    Write-Host "Remove marker created: $removeMarker"
}

# --- Main execution ---
if ($Action -eq "Install") {
    Enable-WinRmHttps
}
elseif ($Action -eq "Remove") {
    Disable-WinRmHttps
}

Stop-Transcript
