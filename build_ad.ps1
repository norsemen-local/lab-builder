<#
.SYNOPSIS
    Script to automate the setup of an Active Directory domain controller, DNS, and DHCP server.

.DESCRIPTION
    This script creates an Active Directory domain controller, configures DNS and DHCP services, and renames the local machine based on a TOPO number from a user file. 
    It ensures that the setup can resume after system reboots which are necessary for certain operations. 
    The script uses the TOPO number from a 'user' file located in the user's profile directory to name both the domain and the domain controller. 
    It also implements error checking to manage potential issues during the setup process.

... [Rest of the header information]

#>

param (
    [string]$DomainController = "",
    [string]$DnsServer = "192.168.3.65",
    [string]$AdminUser = "lab-user",
    [string]$AdminPassword = "Paloalto1!",
    [string[]]$DnsForwarders = @("8.8.8.8", "8.8.4.4")
)

# Script path for rescheduling after reboot
$scriptPath = $MyInvocation.MyCommand.Path

# ... [functions remain unchanged]

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

    # Set DomainController name based on TOPO number if not explicitly provided
    if ([string]::IsNullOrEmpty($DomainController)) {
        $DomainController = "dc-$userTopoNumber"
        Write-Verbose "Using default DomainController name: $DomainController"
    }

    # Set Domain name based on TOPO number, appending .local for full qualification
    $DomainName = "ad-$userTopoNumber.local"
    Write-Verbose "Setting Domain name to $DomainName"

    # Check for pending reboot from previous operations
    if (Test-PendingReboot) {
        Write-Verbose "A reboot is pending. Rebooting now..."
        Restart-Computer -Force
        return
    }

    # Rename the computer only if the new name differs from the current name
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
        Write-Verbose "Skipping rename operation as the new name is the same as the current name."
    }

    # Install Windows Features
    Write-Verbose "Installing Active Directory, DNS, and DHCP roles..."
    try {
        $featureInstallResult = Install-WindowsFeature AD-Domain-Services, DNS, DHCP -IncludeManagementTools -Verbose
        if ($featureInstallResult.RestartNeeded -eq 'Yes') {
            Write-Verbose "A reboot is required after feature installation. Rebooting..."
            Restart-Computer -Force
            return
        }
    } catch {
        Write-Error "Failed to install features: $($_.Exception.Message)"
        exit 1
    }

    # Promote to Domain Controller
    Write-Verbose "Promoting server to Domain Controller..."
    try {
        $SecurePassword = ConvertTo-SecureString -String $AdminPassword -AsPlainText -Force
        Install-ADDSForest -DomainName $DomainName `
                           -DomainNetbiosName $DomainController `
                           -SafeModeAdministratorPassword $SecurePassword `
                           -InstallDNS `
                           -CreateDNSDelegation:$false `
                           -DatabasePath "C:\Windows\NTDS" `
                           -LogPath "C:\Windows\NTDS" `
                           -SysvolPath "C:\Windows\SYSVOL" `
                           -Force `
                           -NoRebootOnCompletion:$false -Verbose
    } catch {
        Write-Error "Failed to promote to Domain Controller: $($_.Exception.Message)"
        exit 1
    }

    # Configure DNS Forwarders
    Write-Verbose "Setting DNS forwarders..."
    foreach ($forwarder in $DnsForwarders) {
        if (-not (Get-DnsServerForwarder | Where-Object { $_.IPAddress -contains $forwarder })) {
            try {
                Write-Verbose "Adding $forwarder as DNS forwarder on server $DomainController."
                Add-DnsServerForwarder -IPAddress $forwarder -PassThru -Verbose
            } catch {
                Write-Error "Failed to add DNS forwarder $forwarder: $($_.Exception.Message)"
            }
        } else {
            Write-Verbose "Forwarder $forwarder is already configured on server $DomainController."
        }
    }

    # Authorize DHCP Server in Active Directory
    Write-Verbose "Authorizing DHCP Server in Active Directory..."
    try {
        Add-DhcpServerInDC -DnsName "$DomainController.$DomainName" -IPAddress (Get-NetIPAddress -AddressFamily IPv4).IPAddress -Verbose
    } catch {
        Write-Error "Failed to authorize DHCP server: $($_.Exception.Message)"
    }

    # Configure DHCP Scope
    Write-Verbose "Setting up DHCP scope..."
    $ScopeParams = @{
        Name       = "Critical"
        StartRange = "192.168.3.50"
        EndRange   = "192.168.3.51"
        SubnetMask = "255.255.255.0"
        State      = "Active"
    }
    try {
        Add-DhcpServerv4Scope @ScopeParams -Verbose
        Set-DhcpServerv4OptionValue -ScopeID "192.168.3.0" -Router "192.168.3.1" -DnsServer $DnsServer -Verbose
    } catch {
        Write-Error "Failed to configure DHCP scope: $($_.Exception.Message)"
    }

    # Restart DHCP Server service
    Write-Verbose "Restarting DHCP Server service..."
    try {
        Restart-Service -Name "DHCPServer" -Force -Verbose
    } catch {
        Write-Error "Failed to restart DHCP service: $($_.Exception.Message)"
    }

    # Ensure DNS Server service is started and set to automatic
    Write-Verbose "Ensuring DNS service is running..."
    try {
        Set-Service -Name "DNS" -StartupType Automatic -Verbose
        Start-Service -Name "DNS" -Verbose
    } catch {
        Write-Error "Failed to configure DNS service: $($_.Exception.Message)"
    }

    # Download and execute fake_net.ps1
    Write-Verbose "Downloading and executing fake_net.ps1..."
    try {
        Download-FakeNet
    } catch {
        Write-Error "Failed to download or execute fake_net.ps1: $($_.Exception.Message)"
    }

    Write-Verbose "Active Directory, DNS, and DHCP setup is complete."

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