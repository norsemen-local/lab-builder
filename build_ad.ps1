<#
.SYNOPSIS
    Script to automate the setup of an Active Directory domain controller, DNS, and DHCP server.

.DESCRIPTION
    This script creates an Active Directory domain controller, configures DNS and DHCP services, and renames the local machine based on a TOPO number from a user file. 
    It ensures that the setup can resume after system reboots which are necessary for certain operations. 
    The script uses the TOPO number from a 'user' file located in the user's profile directory to name both the domain and the domain controller.

.PARAMETER DomainController
    Optional name for the domain controller. If not provided, it will be automatically set to "dc-[TOPO number]".

.PARAMETER DnsServer
    IP address of the DNS server to be set. Default is "192.168.3.65".

.PARAMETER AdminUser
    Administrator username for domain setup. Default is "lab-user".

.PARAMETER AdminPassword
    Password for the admin user. Default is "Paloalto1!". WARNING: This is stored in plain text; for production use, secure this better.

.PARAMETER DnsForwarders
    List of DNS forwarder IP addresses. Default includes Google's public DNS servers.

.EXAMPLE
    .\build_ad.ps1 -Verbose

.NOTES
    File Name      : build_ad.ps1
    Author         : Your Name
    Requires       : PowerShell 5.1 or higher, Windows Server with ADDS, DNS, DHCP features available
    Version        : 1.0
    Date           : Today's Date

    Ensure you run this with administrative privileges. This script will:
        - Create or update a domain
        - Install AD DS, DNS, and DHCP roles
        - Configure these services
        - Restart the machine when necessary
        - Resume script execution after reboot
    
    IMPORTANT: This script modifies system settings and should be used with caution in production environments. Always test in a non-production setup first.

.LINK
    None

#>

param (
    [string]$DomainController = "",
    [string]$DnsServer = "192.168.3.65",
    [string]$AdminUser = "lab-user",
    [string]$AdminPassword = "Paloalto1!",
    [string[]]$DnsForwarders = @("8.8.8.8", "8.8.4.4")
)

$scriptPath = $MyInvocation.MyCommand.Path

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

function Restart-WithResume {
    param (
        [string]$ScriptPath
    )

    # Check if resuming from reboot
    if ($env:REBOOT_RESUME) {
        Write-Verbose "Resuming script after reboot..."
        Remove-Item env:REBOOT_RESUME -Force
    } else {
        Write-Verbose "Setting up for reboot and resume..."
        # Set environment variable to indicate we need to resume post-reboot
        [System.Environment]::SetEnvironmentVariable("REBOOT_RESUME", "true", "Machine")
        
        # Schedule the script to run after reboot
        $taskName = "ResumeBuildADServer"
        $trigger = New-ScheduledTaskTrigger -AtLogon
        $action = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`"" 
        Register-ScheduledTask -TaskName $taskName -Trigger $trigger -Action $action -RunLevel Highest -Force -Verbose

        Write-Verbose "Reboot scheduled. Script will resume after system restart."
        Restart-Computer -Force
    }
}

function Download-FakeNet {
    [CmdletBinding()]
    param(
        [string]$DestinationPath = "$env:USERPROFILE\fake_net.ps1"
    )

    $url = "https://raw.githubusercontent.com/packetalien/fakenet/refs/heads/main/fake_net.ps1"
    $webClient = New-Object System.Net.WebClient
    Write-Verbose "Downloading fake_net.ps1 from Google Drive..."
    try {
        $webClient.DownloadFile($url, $DestinationPath)
        if (Test-Path $DestinationPath) {
            Write-Verbose "fake_net.ps1 downloaded successfully to $DestinationPath"
            & $DestinationPath -Verbose
        } else {
            Write-Error "Failed to download fake_net.ps1"
        }
    } catch {
        Write-Error "An error occurred while downloading or executing fake_net.ps1: $_"
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

    # Set DomainController name based on TOPO number if not explicitly provided
    if ([string]::IsNullOrEmpty($DomainController)) {
        $DomainController = "dc-$userTopoNumber"
        Write-Verbose "Using default DomainController name: $DomainController"
    }

    # Set Domain name based on TOPO number
    $DomainName = "ad-$userTopoNumber"
    Write-Verbose "Setting Domain name to $DomainName"

    # Check if resuming from reboot
    Restart-WithResume -ScriptPath $scriptPath

    # Set the hostname
    Write-Verbose "Renaming computer to $DomainController"
    Rename-Computer -NewName $DomainController -Force

    # Install Windows Features
    Write-Verbose "Installing Active Directory, DNS, and DHCP roles..."
    Install-WindowsFeature AD-Domain-Services, DNS, DHCP -IncludeManagementTools -Verbose

    # Promote to Domain Controller
    Write-Verbose "Promoting server to Domain Controller..."
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

    # If the script gets here, it means no reboot was necessary or it's resuming after reboot
    Write-Verbose "Continuing with post-reboot configuration..."

    # Configure DNS Forwarders
    Write-Verbose "Setting DNS forwarders..."
    foreach ($forwarder in $DnsForwarders) {
        Add-DnsServerForwarder -IPAddress $forwarder -PassThru -Verbose
    }

    # Authorize DHCP Server in Active Directory
    Write-Verbose "Authorizing DHCP Server in Active Directory..."
    Add-DhcpServerInDC -DnsName "$DomainController.$DomainName" -IPAddress (Get-NetIPAddress -AddressFamily IPv4).IPAddress -Verbose

    # Configure DHCP Scope
    Write-Verbose "Setting up DHCP scope..."
    $ScopeParams = @{
        Name       = "Critical"
        StartRange = "192.168.3.50"
        EndRange   = "192.168.3.51"
        SubnetMask = "255.255.255.0"
        State      = "Active"
    }
    Add-DhcpServerv4Scope @ScopeParams -Verbose
    Set-DhcpServerv4OptionValue -ScopeID "192.168.3.0" -Router "192.168.3.1" -DnsServer $DnsServer -Verbose

    # Restart DHCP Server service
    Write-Verbose "Restarting DHCP Server service..."
    Restart-Service -Name "DHCPServer" -Force -Verbose

    # Ensure DNS Server service is started and set to automatic
    Write-Verbose "Ensuring DNS service is running..."
    Set-Service -Name "DNS" -StartupType Automatic -Verbose
    Start-Service -Name "DNS" -Verbose

    # Download and execute fake_net.ps1
    Write-Verbose "Downloading and executing fake_net.ps1..."
    Download-FakeNet

    Write-Verbose "Active Directory, DNS, and DHCP setup is complete."

} catch {
    Write-Error "An error occurred while executing the script: $_"
    exit 1
} finally {
    # Clean up the scheduled task if it exists
    $taskName = "ResumeBuildADServer"
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Write-Verbose "Cleaning up scheduled task $taskName"
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -Verbose
    }
}