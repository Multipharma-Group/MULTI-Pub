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

.NOTES
    Author   : MULTIPHARMA
    Created  : 2025-08-29
    Usage    : Run as Administrator
    Security : Basic authentication should only be used with HTTPS.
    Log File : C:\Scripts\<ScriptBaseName>.log
    Markers  : C:\Scripts\WinRM-Toggle.installed / C:\Scripts\WinRM-Toggle.removed
#>

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("Install","Remove")]
    [string]$Action
)

# --- Check for elevation ---
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Script must run as Administrator!"
    exit
}

# --- Get script name and path ---
$ScriptFullPath = $PSCommandPath
$ScriptName = Split-Path -Path $PSCommandPath -Leaf
$ScriptBaseName = [IO.Path]::GetFileNameWithoutExtension($ScriptName)  # e.g., winRmMgmtIAC4AVD
$ScriptDir = Split-Path -Path $PSCommandPath -Parent

Write-Host "Running script full path: $ScriptFullPath"
Write-Host "Script name: $ScriptName"
Write-Host "Script folder: $ScriptDir"

# --- Setup log file and markers ---
$logDir = "C:\Scripts"
$logFile = Join-Path $logDir "$ScriptBaseName.log"  # dynamic log file based on script base name

$installMarker = Join-Path $logDir "WinRM-Toggle.installed"
$removeMarker  = Join-Path $logDir "WinRM-Toggle.removed"

if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }

Start-Transcript -Path $logFile -Append
Write-Host "Logging to: $logFile"

# --- Exit if the action has already been run ---
if ($Action -eq "Install" -and Test-Path $installMarker) {
    Write-Host "Install action already executed. Exiting."
    Stop-Transcript
    exit
}
if ($Action -eq "Remove" -and Test-Path $removeMarker) {
    Write-Host "Remove action already executed. Exiting."
    Stop-Transcript
    exit
}

# --- Variables ---
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
    $existingListeners = winrm enumerate winrm/config/Listener | Where-Object { $_ -match "Transport = HTTPS" }
    if ($existingListeners) {
        Write-Host "Removing existing HTTPS listener(s)..."
        winrm delete winrm/config/Listener?Address=*+Transport=HTTPS
    } else {
        Write-Host "No HTTPS listener found. Skipping deletion..."
    }

    $listenerSettings = "@{Hostname=`"$myDNSHost`";CertificateThumbprint=`"$thumbprint`"}"
    winrm create winrm/config/Listener?Address=*+Transport=HTTPS $listenerSettings
    Write-Host "WinRM HTTPS listener created."

    # --- Correct Basic authentication logic ---
    Write-Host "Enabling Basic authentication..."
    $authPath = "WSMan:\localhost\Service\Auth"
    Set-Item -Path "$authPath\Basic" -Value $true
    Restart-Service WinRM -Force
    $currentValue = (Get-Item "$authPath\Basic").Value
    Write-Host "Basic authentication is now set to: $currentValue"

    # Create install marker
    New-Item -ItemType File -Path $installMarker -Force | Out-Null
    Write-Host "Install marker created at $installMarker. Install will not run again."

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

    # --- Disable Basic authentication ---
    Write-Host "Disabling Basic authentication..."
    $authPath = "WSMan:\localhost\Service\Auth"
    Set-Item -Path "$authPath\Basic" -Value $false
    Restart-Service WinRM -Force
    $currentValue = (Get-Item "$authPath\Basic").Value
    Write-Host "Basic authentication is now set to: $currentValue"

    # Create remove marker
    New-Item -ItemType File -Path $removeMarker -Force | Out-Null
    Write-Host "Remove marker created at $removeMarker. Remove will not run again."

    Write-Host "=== Removal complete ==="
}

# --- Stop logging ---
Stop-Transcript
Write-Host "All actions logged to $logFile"
