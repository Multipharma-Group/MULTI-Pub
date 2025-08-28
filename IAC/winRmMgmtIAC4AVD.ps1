# --- Enable WinRM and Configure Firewall ---

# Enable PowerShell remoting (sets up WinRM service, listeners, and firewall rules by default).
Enable-PSRemoting -Force

# Add firewall rule to allow WinRM traffic over HTTP (port 5985).
netsh advfirewall firewall add rule name="WinRM-HTTP" dir=in localport=5985 protocol=TCP action=allow

# Add firewall rule to allow WinRM traffic over HTTPS (port 5986).
netsh advfirewall firewall add rule name="WinRM-HTTPS" dir=in localport=5986 protocol=TCP action=allow

# (Optional) Remove existing HTTPS listener if one already exists.
# winrm delete winrm/config/Listener?Address=*+Transport=HTTPS


# --- Create Self-Signed SSL Certificate for HTTPS WinRM ---

# Get the current hostname (computer name).
$myHost = hostname

# Define the domain part for the fully qualified domain name (FQDN).
$myDomain = "multi.be"

# Combine host and domain to form the FQDN (DNS name).
$myDNSHost = $myHost + "." + $myDomain

# Generate a new self-signed certificate for the host FQDN and place it in the Local Machine certificate store.
$cert = New-SelfSignedCertificate -DnsName $myDNSHost -CertStoreLocation Cert:\LocalMachine\My

# Extract the certificate thumbprint for use in WinRM listener configuration.
$thumbprint = $cert.Thumbprint

# Prepare the listener configuration with hostname and certificate thumbprint.
$listener = "@{Hostname=""$myDNSHost"";CertificateThumbprint=""$thumbprint""}"

# Create a new WinRM HTTPS listener bound to the FQDN with the certificate.
winrm create winrm/config/Listener?Address=*+Transport=HTTPS $listener


# --- Firewall Rule for HTTPS (Redundant, but ensures port is open) ---

netsh advfirewall firewall add rule name="WinRM-HTTPS" dir=in localport=5986 protocol=TCP action=allow


# --- Enable Authentication ---

# Enable Basic authentication (needed for some management tools; consider security implications).
Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $true
