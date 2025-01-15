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
    $RegPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds"

    # Check if the key exists, if not, create it
    if (-not (Test-Path $RegPath)) {
        New-Item -Path $RegPath -Force | Out-Null
    }

    # Set the registry value to disable News and Interests
    Set-ItemProperty -Path $RegPath -Name ShellFeedsTaskbarViewMode -Value 2 -Type DWord

    # Restart explorer to apply changes
    Stop-Process -Name explorer -Force
    Write-Host "News and Interests on the taskbar has been disabled."
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

# Main execution
try {
    # Create Scripts directory
    New-ScriptsDirectory
    
    # Download EDU-XSIAM-Engineer-Example.py to Scripts directory
    $scriptURL = "https://raw.githubusercontent.com/norsemen-local/lab-builder/refs/heads/main/EDU-XSIAM-Engineer-Example.py"
    $scriptDestination = "$env:USERPROFILE\Desktop\Scripts\EDU-XSIAM-Engineer-Example.py"
    Download-Script -URL $scriptURL -Destination $scriptDestination

    # Disable News and Interests
    Disable-NewsAndInterests

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

    $serverInfo = @(
        "Windows Server Information:",
        "Name: dc-$topoNumber",
        "IP: 192.168.3.65",
        "Username: lab-user",
        "Password: Paloalto1!",
        "AD Username: Administratorad-$topoNumber.local",
        "AD Password: Paloalto1!",
        "FQDN: dc-$topoNumber.ad-$topoNumber.local",
        "",
        "Linux Server Information:",
        "Name: ubuntu",
        "IP: 192.168.3.66",
        "Username: lab-user",
        "Password: Paloalto1!",
        "To Access Kubernetes for CDR Agent, log in to Linux Server and run the followng command:",
        "sudo microk8s kubectl exec -it alpine-cdr-1 -- sh",
        "Setup Commands (already run for you):",
        "sudo snap install microk8s --classic",
        "wget https://raw.githubusercontent.com/hankthebldr/CDR/refs/heads/master/cdr.yml",
        "sudo microk8s kubectl apply -f cdr.yml"
    )

    # Output server information
    Write-Host "Server Information:"
    $serverInfo | ForEach-Object { Write-Host $_ }

    # Append server information to lab-build.txt with a new line at the start
    $labBuildPath = "$env:USERPROFILE\Desktop\lab-build.txt"
    "`n" | Add-Content -Path $labBuildPath  # Add a new line at the start
    $serverInfo | Add-Content -Path $labBuildPath

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