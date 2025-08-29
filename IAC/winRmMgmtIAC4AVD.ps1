<#
.SYNOPSIS
  Configure or remove WinRM HTTPS listener for Azure Virtual Desktop (AVD).

.DESCRIPTION
  This script sets up or removes a WinRM HTTPS listener on port 5986,
  including creating a self-signed certificate, firewall rule, and enabling Basic authentication.

  It is designed to run once during VM provisioning via Ansible (CustomScriptExtension).
  It uses marker files to avoid re-running the same action multiple times.

.PARAMETER Action
  Install : Configure WinRM HTTPS listener (default).
  Remove  : Remove WinRM HTTPS listener and disable Basic auth.

#>

param (
    [Parameter(Mandatory = $false)]
    [ValidateSet("Install", "Remove")]
    [string]$Action = "Install"
)

# --- Setup paths and logging ---
$ScriptName      = $MyInvocation.MyCommand.Name
$ScriptBaseName  = [System.IO.Path]::GetFileNameWithoutExtension($ScriptName)

$logDir = "C:\Scripts"
if (-not (Test-Path $logDir)) { 
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null 
}

$logFile         = Join-Path $logDir "$ScriptBaseName.log"
$installMarker   = Join-Path $logDir "WinRM-Toggle.installed"
$removeMarker    = Join-Path $logDir "WinRM-Toggle.removed"

Start-Transcript -Path $logFile -Append

Write-Host "Running $ScriptName with Action = $Action"

# --- Skip execution if already done ---
if ($Action -eq "Install" -and (Test-Path $installMarker)) {
    Write-Host "Install already completed. Exiting."
    Stop-Transcript
    exit 0
}
if ($Action -eq "Remove" -and (Test-Path $removeMarker)) {
    Write-Host "Remove already completed. Exiting."
    Stop-Transcript
    exit 0
}

try {
    if ($Action -eq "Install") {
        Write-Host "Enabling PSRemoting..."
        Enable-PSRemoting -Force

        Write-Host "Creating self-signed certificate..."
        $myHost    = hostname
        $myDomain  = "multi.be"
        $myDNSHost = "$myHost.$myDomain"
        $cert      = New-SelfSignedCertificate -DnsName $myDNSHost -CertStoreLocation Cert:\LocalMachine\My
        $thumb     = $cert.Thumbprint

        # Remove existing HTTPS listener if any
        if (winrm enumerate winrm/config/Listener | Select-String "Transport = HTTPS") {
            Write-Host "Removing existing WinRM HTTPS listener..."
            winrm delete winrm/config/Listener?Address=*+Transport=HTTPS
        }

        Write-Host "Creating WinRM HTTPS listener..."
        $listener = "@{Hostname=`"$myDNSHost`";CertificateThumbprint=`"$thumb`"}"
        winrm create winrm/config/Listener?Address=*+Transport=HTTPS $listener

        Write-Host "Configuring firewall for WinRM over HTTPS (5986)..."
        netsh advfirewall firewall add rule name="WinRM-HTTPS" dir=in localport=5986 protocol=TCP action=allow

        Write-Host "Enabling Basic authentication..."
        $authPath = "WSMan:\localhost\Service\Auth\Basic"
        Set-Item -Path $authPath -Value $true
        Restart-Service WinRM -Force
        $current = (Get-Item $authPath).Value
        Write-Host "Basic authentication is now set to: $current"

        New-Item -ItemType File -Path $installMarker -Force | Out-Null
    }
    elseif ($Action -eq "Remove") {
        Write-Host "Removing WinRM HTTPS listener..."
        winrm delete winrm/config/Listener?Address=*+Transport=HTTPS

        Write-Host "Disabling Basic authentication..."
        $authPath = "WSMan:\localhost\Service\Auth\Basic"
        Set-Item -Path $authPath -Value $false
        Restart-Service WinRM -Force

        Write-Host "Removing firewall rule..."
        netsh advfirewall firewall delete rule name="WinRM-HTTPS"

        New-Item -ItemType File -Path $removeMarker -Force | Out-Null
    }

    # --- Finalize ---
    Write-Host "=== Action $Action completed successfully ==="
    Stop-Transcript
    exit 0
}
catch {
    Write-Host "ERROR: $($_.Exception.Message)"
    Stop-Transcript
    exit 1
}
