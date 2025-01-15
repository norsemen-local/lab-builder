<#
.SYNOPSIS
    Script to automate the setup of an Active Directory domain controller, DNS, and DHCP server with configuration checks.

.DESCRIPTION
    This script checks the current configuration of the server and only performs necessary actions to set up an AD domain controller, DNS, and DHCP server based on a TOPO number from a user file. 
    It ensures that the setup can resume after system reboots which are necessary for certain operations, including logging in as the Administrator of the newly created domain.

... [Rest of the header information]

#>

param (
    [string]$DnsServer = "192.168.3.65",
    [string]$AdminUser = "lab-user",
    [string]$AdminPassword = "Paloalto1!",
    [string[]]$DnsForwarders = @("8.8.8.8", "8.8.4.4")
)

# Script path for rescheduling after reboot
$scriptPath = $MyInvocation.MyCommand.Path

# Function to get TOPO number from user file
function Get-UserTopoNumber {
    param (
        [string]$FilePath = "$env:USERPROFILE\user"
    )
    
    if (-Not (Test-Path -Path $FilePath)) {
        Write-Error "The file '$FilePath' does not exist."
        return $null
    }

    $firstLine = Get-Content -Path $FilePath -TotalCount 1

    if ($firstLine -match 'TOPO=(\d{4,5})') {
        # Convert matched string to integer
        return [int]$matches[1]
    } else {
        Write-Warning "The first line does not contain 'TOPO=' followed by a 4 or 5 digit number."
        return $null
    }
}

# Function to test if domain is already configured
function Test-DomainConfigured {
    param (
        [string]$DomainName
    )
    try {
        $domain = Get-ADDomain -ErrorAction Stop
        return $domain.DnsRoot -eq $DomainName
    } catch {
        return $false
    }
}

# Function to check if DHCP server is authorized
function Test-DhcpServerAuthorized {
    param (
        [string]$DnsName
    )
    try {
        $dhcpServers = Get-DhcpServerInDC
        return $dhcpServers | Where-Object { $_.DnsName -eq $DnsName }
    } catch {
        return $false
    }
}

# Function to check if DHCP scope is configured
function Test-DhcpScopeConfigured {
    param (
        [string]$ScopeID
    )
    try {
        $scopes = Get-DhcpServerv4Scope
        return $scopes | Where-Object { $_.ScopeId -eq [System.Net.IPAddress]::Parse($ScopeID) }
    } catch {
        return $false
    }
}

# Function to check if DNS forwarders are configured
function Test-DnsForwardersConfigured {
    param (
        [string[]]$Forwarders
    )
    $configuredForwarders = Get-DnsServerForwarder | Select-Object -ExpandProperty IPAddress
    foreach ($forwarder in $Forwarders) {
        if ($configuredForwarders -notcontains $forwarder) {
            return $false
        }
    }
    return $true
}

# Function for reboot management
function Restart-WithResume {
    param (
        [string]$ScriptPath
    )
    if ($env:REBOOT_RESUME) {
        Write-Verbose "Resuming script after reboot..."
        Remove-Item env:REBOOT_RESUME -Force
    } else {
        Write-Verbose "Setting up for reboot and resume..."
        # Set environment variable to indicate we need to resume post-reboot
        [System.Environment]::SetEnvironmentVariable("REBOOT_RESUME", "true", "Machine")
        
        # Schedule the script to run after reboot as domain admin
        $taskName = "ResumeBuildADServer"
        $domainName = "ad-$userTopoNumber.local"
        $domainAdminAccount = "Administrator@$domainName"
        $trigger = New-ScheduledTaskTrigger -AtLogon
        $action = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" -RunAsUser $domainAdminAccount -RunAsPassword $AdminPassword"
        Register-ScheduledTask -TaskName $taskName -Trigger $trigger -Action $action -RunLevel Highest -Force -Verbose

        Write-Verbose "Reboot scheduled. Script will resume as $domainAdminAccount after system restart."
        Restart-Computer -Force
    }
}

# Function to download and execute fakenet.ps1 from GitHub
function Download-FakeNet {
    [CmdletBinding()]
    param(
        [string]$DestinationPath = "$env:USERPROFILE\fakenet.ps1"
    )

    $url = "https://raw.githubusercontent.com/norsemen-local/lab-builder/refs/heads/main/fakenet.ps1"
    $webClient = New-Object System.Net.WebClient
    Write-Verbose "Downloading fakenet.ps1 from GitHub..."
    try {
        $webClient.DownloadFile($url, $DestinationPath)
        if (Test-Path -Path $DestinationPath) {
            Write-Verbose "fakenet.ps1 downloaded successfully to $DestinationPath"
            & $DestinationPath -Verbose
        } else {
            Write-Error "Failed to download fakenet.ps1"
        }
    } catch {
        Write-Error "An error occurred while downloading or executing fakenet.ps1: $($_.Exception.Message)"
    }
}

# Function to check if NetBIOS name exists on the network
function Test-NetBIOSNameExists {
    param (
        [string]$Name
    )
    try {
        $result = ([System.Net.Dns]::GetHostEntry($Name))
        return $true
    } catch {
        return $false
    }
}

try {
    # Set Execution Policy to Unrestricted for this session
    Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process -Force -Verbose

    # Default file path for user file
    $UserFilePath = "$env:USERPROFILE\user"
    Write-Verbose "Looking for user file at $UserFilePath"

    # Get TOPO number from user file
    $userTopoNumber = Get-UserTopoNumber -FilePath $UserFilePath
    if ($null -eq $userTopoNumber) {
        Write-Error "Failed to retrieve TOPO number from user file. Script cannot continue."
        return
    }

    $DomainName = "ad-$userTopoNumber.local"
    $DomainNetBiosName = "ad-$userTopoNumber"
    $DomainController = "dc-$userTopoNumber"

    # Check and rename computer if necessary
    $currentName = [System.Net.Dns]::GetHostName()
    if ($currentName -ne $DomainController) {
        Write-Verbose "Renaming computer from '$currentName' to '$DomainController'"
        try {
            Rename-Computer -NewName $DomainController -Force -Verbose
            Write-Verbose "Computer name changed. Scheduling reboot to apply changes..."
            Restart-WithResume -ScriptPath $scriptPath
        } catch {
            Write-Error "Failed to rename computer: $($_.Exception.Message)"
            exit 1
        }
    } else {
        Write-Verbose "Computer name is correct. Skipping rename."
    }

    # Install Windows Features if not already installed
    Write-Verbose "Checking if Active Directory, DNS, and DHCP roles are installed..."
    $requiredFeatures = Get-WindowsFeature | Where-Object { $_.Name -in @('AD-Domain-Services', 'DNS', 'DHCP') }
    if ($requiredFeatures | Where-Object { $_.Installed -eq $false }) {
        Write-Verbose "Installing Active Directory, DNS, and DHCP roles..."
        try {
            $featureInstallResult = Install-WindowsFeature AD-Domain-Services, DNS, DHCP -IncludeManagementTools -Verbose
            if ($featureInstallResult.RestartNeeded -eq 'Yes') {
                Write-Verbose "A reboot is required after feature installation. Rebooting..."
                Restart-WithResume -ScriptPath $scriptPath
                return
            }
        } catch {
            Write-Error "Failed to install features: $($_.Exception.Message)"
            exit 1
        }
    } else {
        Write-Verbose "All required features are already installed. Skipping installation."
    }

    # Promote to Domain Controller if not already configured
    if (-not (Test-DomainConfigured -DomainName $DomainName)) {
        Write-Verbose "Promoting server to Domain Controller..."
        $uniqueNetBiosName = $DomainNetBiosName
        $counter = 1
        while (Test-NetBIOSNameExists -Name $uniqueNetBiosName) {
            $uniqueNetBiosName = "$DomainNetBiosName-$counter"
            $counter++
            Write-Verbose "NetBIOS name conflict detected. Changing to $uniqueNetBiosName"
        }

        try {
            $SecurePassword = ConvertTo-SecureString -String $AdminPassword -AsPlainText -Force
            Install-ADDSForest -DomainName $DomainName `
                               -DomainNetbiosName $uniqueNetBiosName `
                               -SafeModeAdministratorPassword $SecurePassword `
                               -InstallDNS `
                               -CreateDNSDelegation:$false `
                               -DatabasePath "C:\Windows\NTDS" `
                               -LogPath "C:\Windows\NTDS" `
                               -SysvolPath "C:\Windows\SYSVOL" `
                               -Force `
                               -NoRebootOnCompletion:$false -Verbose
            Write-Verbose "Domain controller promotion complete. Rebooting to finalize..."
            Restart-WithResume -ScriptPath $scriptPath
        } catch {
            Write-Error "Failed to promote to Domain Controller: $($_.Exception.Message)"
            exit 1
        }
    } else {
        Write-Verbose "Domain $DomainName is already configured. Skipping promotion."
    }

    # Continue with configuration after domain promotion
    if ($env:REBOOT_RESUME -eq "true") {
        Write-Verbose "Resuming configuration after domain controller promotion..."
        
        # Check and configure DNS forwarders
        if (-not (Test-DnsForwardersConfigured -Forwarders $DnsForwarders)) {
            Write-Verbose "Setting DNS forwarders..."
            foreach ($forwarder in $DnsForwarders) {
                if (-not (Get-DnsServerForwarder | Where-Object { $_.IPAddress -contains $forwarder })) {
                    try {
                        Write-Verbose "Adding $forwarder as DNS forwarder on server $DomainController."
                        Add-DnsServerForwarder -IPAddress $forwarder -PassThru -Verbose
                    } catch {
                        Write-Error "Failed to add DNS forwarder $forwarder $($_.Exception.Message)"
                    }
                } else {
                    Write-Verbose "Forwarder $forwarder is already configured on server $DomainController."
                }
            }
        } else {
            Write-Verbose "All specified DNS forwarders are already configured. Skipping setup."
        }

        # Authorize DHCP Server in Active Directory if not already done
        if (-not (Test-DhcpServerAuthorized -DnsName "$DomainController.$DomainName")) {
            Write-Verbose "Authorizing DHCP Server in Active Directory..."
            try {
                # Get only the first IPv4 address for authorization
                $ip = (Get-NetIPAddress -AddressFamily IPv4 | Select-Object -First 1).IPAddress
                Add-DhcpServerInDC -DnsName "$DomainController.$DomainName" -IPAddress $ip -Verbose
            } catch {
                Write-Error "Failed to authorize DHCP server: $($_.Exception.Message)"
            }
        } else {
            Write-Verbose "DHCP server is already authorized. Skipping authorization."
        }

        # Configure DHCP Scope if not already configured
        if (-not (Test-DhcpScopeConfigured -ScopeID "192.168.3.0")) {
            Write-Verbose "Setting up DHCP scope..."
            $ScopeParams = @{
                Name       = "Critical"
                StartRange = "192.168.3.50"
                EndRange   = "192.168.3.51"
                SubnetMask = "255.255.255.0"
                State      = "Active"
            }
            try {
                # Ensure DHCP server is running before adding scope
                $dhcpServerStatus = Get-Service -Name DHCPServer
                if ($dhcpServerStatus.Status -ne 'Running') {
                    Write-Verbose "Starting DHCP server service..."
                    Start-Service -Name DHCPServer
                }
                
                Add-DhcpServerv4Scope @ScopeParams -Verbose
                if ([System.Net.IPAddress]::TryParse($DnsServer, [ref]$null)) {
                    Set-DhcpServerv4OptionValue -ScopeID "192.168.3.0" -Router "192.168.3.1" -DnsServer $DnsServer -Verbose
                } else {
                    Write-Error "Invalid DNS server IP address: $DnsServer"
                }
            } catch {
                Write-Error "Failed to configure DHCP scope: $($_.Exception.Message)"
            }
        } else {
            Write-Verbose "DHCP scope is already configured. Skipping setup."
        }

        # Download and execute fakenet.ps1
        Write-Verbose "Downloading and executing fakenet.ps1..."
        try {
            Download-FakeNet
        } catch {
            Write-Error "Failed to download or execute fakenet.ps1: $($_.Exception.Message)"
        }

        Write-Verbose "Active Directory, DNS, and DHCP setup is complete."
    }

} catch {
    Write-Error "An error occurred while executing the script: $($_.Exception.Message)"
    exit 1
} finally {
    # Clean up the scheduled task if it exists
    $taskName = "ResumeBuildADServer"
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Write-Verbose "Cleaning up scheduled task $taskName"
        try {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -Verbose
        } catch {
            Write-Error "Failed to unregister scheduled task: $($_.Exception.Message)"
        }
    }
}