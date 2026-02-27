#Requires -Version 3.0

# Configure a Windows host for remote management with Ansible
# -----------------------------------------------------------

[CmdletBinding()]
Param (
    [string]$SubjectName = $env:COMPUTERNAME,
    [int]$CertValidityDays = 1095,
    [switch]$SkipNetworkProfileCheck,
    $CreateSelfSignedCert = $true,
    [switch]$ForceNewSSLCert,
    [switch]$GlobalHttpFirewallAccess,
    [switch]$DisableBasicAuth = $false,
    [switch]$EnableCredSSP
)

Function Write-Log { $Message = $args[0]; Write-EventLog -LogName Application -Source $EventSource -EntryType Information -EventId 1 -Message $Message }
Function Write-VerboseLog { $Message = $args[0]; Write-Verbose $Message; Write-Log $Message }
Function Write-HostLog { $Message = $args[0]; Write-Output $Message; Write-Log $Message }

Function New-LegacySelfSignedCert {
    Param ([string]$SubjectName, [int]$ValidDays = 1095)
    $hostnonFQDN = $env:computerName
    $hostFQDN = [System.Net.Dns]::GetHostByName(($env:computerName)).Hostname
    $SignatureAlgorithm = "SHA256"

    $name = New-Object -COM "X509Enrollment.CX500DistinguishedName.1"
    $name.Encode("CN=$SubjectName", 0)
    $key = New-Object -COM "X509Enrollment.CX509PrivateKey.1"
    $key.ProviderName = "Microsoft Enhanced RSA and AES Cryptographic Provider"
    $key.KeySpec = 1; $key.Length = 4096; $key.SecurityDescriptor = "D:PAI(A;;0xd01f01ff;;;SY)(A;;0xd01f01ff;;;BA)(A;;0x80120089;;;NS)"
    $key.MachineContext = 1; $key.Create()

    $serverauthoid = New-Object -COM "X509Enrollment.CObjectId.1"
    $serverauthoid.InitializeFromValue("1.3.6.1.5.5.7.3.1")
    $ekuoids = New-Object -COM "X509Enrollment.CObjectIds.1"; $ekuoids.Add($serverauthoid)
    $ekuext = New-Object -COM "X509Enrollment.CX509ExtensionEnhancedKeyUsage.1"; $ekuext.InitializeEncode($ekuoids)

    $cert = New-Object -COM "X509Enrollment.CX509CertificateRequestCertificate.1"
    $cert.InitializeFromPrivateKey(2, $key, ""); $cert.Subject = $name; $cert.Issuer = $cert.Subject
    $cert.NotBefore = (Get-Date).AddDays(-1); $cert.NotAfter = $cert.NotBefore.AddDays($ValidDays)
    $SigOID = New-Object -ComObject X509Enrollment.CObjectId; $SigOID.InitializeFromValue(([Security.Cryptography.Oid]$SignatureAlgorithm).Value)

    [string[]] $AlternativeName += $hostnonFQDN; $AlternativeName += $hostFQDN
    $IAlternativeNames = New-Object -ComObject X509Enrollment.CAlternativeNames
    foreach ($AN in $AlternativeName) { $AltName = New-Object -ComObject X509Enrollment.CAlternativeName; $AltName.InitializeFromString(0x3,$AN); $IAlternativeNames.Add($AltName) }
    $SubjectAlternativeName = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames; $SubjectAlternativeName.InitializeEncode($IAlternativeNames)

    [String[]]$KeyUsage = ("DigitalSignature", "KeyEncipherment")
    $KeyUsageObj = New-Object -ComObject X509Enrollment.CX509ExtensionKeyUsage
    $KeyUsageObj.InitializeEncode([int][Security.Cryptography.X509Certificates.X509KeyUsageFlags]($KeyUsage)); $KeyUsageObj.Critical = $true
    $cert.X509Extensions.Add($KeyUsageObj); $cert.X509Extensions.Add($ekuext); $cert.SignatureInformation.HashAlgorithm = $SigOID
    $CERT.X509Extensions.Add($SubjectAlternativeName); $cert.Encode()

    $enrollment = New-Object -COM "X509Enrollment.CX509Enrollment.1"; $enrollment.InitializeFromRequest($cert)
    $certdata = $enrollment.CreateRequest(0); $enrollment.InstallResponse(2, $certdata, 0, "")

    $parsed_cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    $parsed_cert.Import([System.Text.Encoding]::UTF8.GetBytes($certdata))
    return $parsed_cert.Thumbprint
}

Function Enable-GlobalHttpFirewallAccess {
    Write-Verbose "Forcing global HTTP firewall access"
    $fw = New-Object -ComObject HNetCfg.FWPolicy2; $add_rule = $false
    $matching_rules = $fw.Rules | Where-Object { $_.Name -eq "Windows Remote Management (HTTP-In)" }; $rule = $null
    If ($matching_rules) {
        If ($matching_rules -isnot [Array]) { $rule = $matching_rules } else { $rule = $matching_rules | ForEach-Object { $_.Profiles -band 4 }[0]; If (-not $rule -or $rule -is [Array]) { $rule = $matching_rules[0] } }
    }
    If (-not $rule) { $rule = New-Object -ComObject HNetCfg.FWRule; $rule.Name = "Windows Remote Management (HTTP-In)"; $rule.Description = "Inbound rule for Windows Remote Management via WS-Management. [TCP 5985]"; $add_rule = $true }

    $rule.Profiles = 0x7FFFFFFF; $rule.Protocol = 6; $rule.LocalPorts = 5985; $rule.RemotePorts = "*"; $rule.LocalAddresses = "*"; $rule.RemoteAddresses = "*"
    $rule.Enabled = $true; $rule.Direction = 1; $rule.Action = 1; $rule.Grouping = "Windows Remote Management"
    If ($add_rule) { $fw.Rules.Add($rule) }
    Write-Verbose "HTTP firewall rule $($rule.Name) updated"
}

# Setup error handling
Trap { Write-Output $_ }; $ErrorActionPreference = "Continue"

# Ensure admin privileges
$myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
$adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator
If (-Not $myWindowsPrincipal.IsInRole($adminRole)) { Write-Output "ERROR: You need elevated Administrator privileges."; Exit 2 }

$EventSource = $MyInvocation.MyCommand.Name
If (-Not $EventSource) { $EventSource = "Powershell CLI" }
If ([System.Diagnostics.EventLog]::Exists('Application') -eq $False -or [System.Diagnostics.EventLog]::SourceExists($EventSource) -eq $False) { New-EventLog -LogName Application -Source $EventSource }

If ($PSVersionTable.PSVersion.Major -lt 3) { Write-Log "PowerShell v3+ required."; Throw "PowerShell v3+ required." }

# Start WinRM
If (!(Get-Service "WinRM")) { Write-Log "WinRM not found."; Throw "WinRM not found." }
ElseIf ((Get-Service "WinRM").Status -ne "Running") { Set-Service -Name "WinRM" -StartupType Automatic; Start-Service -Name "WinRM"; Write-Log "WinRM started." }

# Enable PS Remoting if needed
If (!(Get-PSSessionConfiguration -Verbose:$false) -or (!(Get-ChildItem WSMan:\localhost\Listener))) {
    If ($SkipNetworkProfileCheck) { Enable-PSRemoting -SkipNetworkProfileCheck -Force; Write-Log "Enabled PS Remoting without network check" }
    Else { Enable-PSRemoting -Force; Write-Log "Enabled PS Remoting" }
}

# Set LocalAccountTokenFilterPolicy
$token_path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$token_prop_name = "LocalAccountTokenFilterPolicy"
$token_key = Get-Item -Path $token_path
$token_value = $token_key.GetValue($token_prop_name, $null)
If ($token_value -ne 1) { If ($null -ne $token_value) { Remove-ItemProperty -Path $token_path -Name $token_prop_name }; New-ItemProperty -Path $token_path -Name $token_prop_name -Value 1 -PropertyType DWORD > $null }

# SSL Listener
$listeners = Get-ChildItem WSMan:\localhost\Listener
$httpsListener = $listeners | Where-Object {$_.Keys -like "TRANSPORT=HTTPS"}
$existingCert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -like "*CN=$SubjectName*" } | Sort-Object NotAfter -Descending | Select-Object -First 1
$useCertThumbprint = $null

If ($existingCert -and $httpsListener) {
    $listenerCertThumb = $httpsListener.CertificateThumbprint
    If ($listenerCertThumb -eq $existingCert.Thumbprint) { $useCertThumbprint = $existingCert.Thumbprint; Write-HostLog "Existing certificate bound" }
}

If (-not $useCertThumbprint) {
    If (-not $existingCert -or $ForceNewSSLCert) { $newThumbprint = New-LegacySelfSignedCert -SubjectName $SubjectName -ValidDays $CertValidityDays; Write-HostLog "New self-signed cert $newThumbprint"; $existingCert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $newThumbprint } }
    $useCertThumbprint = $existingCert.Thumbprint
    If ($httpsListener) { Remove-WSManInstance -ResourceURI 'winrm/config/Listener' -SelectorSet @{Address='*';Transport='HTTPS'} }
    New-WSManInstance -ResourceURI 'winrm/config/Listener' -SelectorSet @{Address='*'; Transport='HTTPS'} -ValueSet @{Hostname=$SubjectName; CertificateThumbprint=$useCertThumbprint}
    Write-HostLog "HTTPS listener created; thumbprint $useCertThumbprint"
} Else { Write-HostLog "HTTPS listener already configured" }

# Basic auth
$basicAuthSetting = Get-ChildItem WSMan:\localhost\Service\Auth | Where-Object {$_.Name -eq "Basic"}
If ($DisableBasicAuth) { If ($basicAuthSetting.Value) { Set-Item -Path "WSMan:\localhost\Service\Auth\Basic" -Value $false; Write-Log "Disabled basic auth" } }
Else { If (-not $basicAuthSetting.Value) { Set-Item -Path "WSMan:\localhost\Service\Auth\Basic" -Value $true; Write-Log "Enabled basic auth" } }

# CredSSP
If ($EnableCredSSP) { $credsspAuthSetting = Get-ChildItem WSMan:\localhost\Service\Auth | Where-Object {$_.Name -eq "CredSSP"}; If (-not $credsspAuthSetting.Value) { Enable-WSManCredSSP -role server -Force; Write-Log "Enabled CredSSP" } }

# Firewall
If ($GlobalHttpFirewallAccess) { Enable-GlobalHttpFirewallAccess }
$fwtest1 = netsh advfirewall firewall show rule name="Allow WinRM HTTPS"
$fwtest2 = netsh advfirewall firewall show rule name="Allow WinRM HTTPS" profile=any
If ($fwtest1.count -lt 5) { netsh advfirewall firewall add rule profile=any name="Allow WinRM HTTPS" dir=in localport=5986 protocol=TCP action=allow; Write-Log "Added firewall rule for WinRM HTTPS" }
ElseIf (($fwtest1.count -ge 5) -and ($fwtest2.count -lt 5)) { netsh advfirewall firewall set rule name="Allow WinRM HTTPS" new profile=any; Write-Log "Updated firewall rule for WinRM HTTPS" }

# Ensure RDP service
$rdpService = Get-Service -Name TermService -ErrorAction SilentlyContinue
If ($rdpService.Status -ne "Running") { Set-Service -Name TermService -StartupType Automatic; Start-Service -Name TermService; Write-HostLog "RDP started" }

# Ensure firewall allows RDP
$rdpRuleCheck = netsh advfirewall firewall show rule name="Allow RDP"
If ($rdpRuleCheck.Count -lt 5) { netsh advfirewall firewall add rule name="Allow RDP" protocol=TCP dir=in localport=3389 action=allow profile=any; Write-HostLog "Firewall rule added for RDP" }

# Test local WinRM and RDP connectivity
Write-VerboseLog "Testing local WinRM and RDP connectivity..."
$httpResult = Invoke-Command -ComputerName "localhost" -ScriptBlock {$env:COMPUTERNAME} -ErrorAction SilentlyContinue
$httpsOptions = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$httpsResult = New-PSSession -UseSSL -ComputerName "localhost" -SessionOption $httpsOptions -ErrorAction SilentlyContinue
$rdpTest = Test-NetConnection -ComputerName "localhost" -Port 3389 -WarningAction SilentlyContinue

If ($httpResult -and $httpsResult) { Write-HostLog "WinRM: HTTP Enabled | HTTPS Enabled" }
ElseIf ($httpsResult -and -not $httpResult) { Write-HostLog "WinRM: HTTP Disabled | HTTPS Enabled" }
ElseIf ($httpResult -and -not $httpsResult) { Write-HostLog "WinRM: HTTP Enabled | HTTPS Disabled" }
Else { Write-Log "WinRM test failed"; Throw "WinRM test failed" }

If ($rdpTest.TcpTestSucceeded) { Write-HostLog "RDP port 3389 reachable" }
Else { Write-Log "RDP test failed"; Throw "RDP test failed" }

# Ensure Google Guest Agent
Set-Service -Name GCEAgent -StartupType Automatic -ErrorAction SilentlyContinue
Start-Service -Name GCEAgent -ErrorAction SilentlyContinue

Exit 0
