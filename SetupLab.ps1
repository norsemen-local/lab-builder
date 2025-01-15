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
    $filePaths = @("$env:USERPROFILE\user", "$env:USERPROFILE\Desktop\lab-build.txt")

    foreach ($path in $filePaths) {
        if (Test-Path -Path $path) {
            $firstLine = Get-Content -Path $path -TotalCount 1

            if ($firstLine -match 'TOPO=(\d{4,5})') {
                # Convert matched string to integer
                return [int]$matches[1]
            }
        }
    }

    Write-Error "No valid TOPO number found in user files. Script cannot continue."
    return $null
}

# Function to create a Scripts directory on the desktop
function New-ScriptsDirectory {
    $scriptsPath = "$env:USERPROFILE\Desktop\Scripts"
    if (-not (Test-Path $scriptsPath)) {
        New-Item -Path $scriptsPath -ItemType Directory | Out-Null
        Write-Verbose "Created Scripts directory at $scriptsPath"
    } else {
        Write-Verbose "Scripts directory already exists at $scriptsPath"
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
        Write-Verbose "Successfully downloaded script to $Destination"
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

    Write-Verbose "News and Interests on the taskbar have been disabled."
}

# Function to check if News and Interests are disabled
function Test-NewsAndInterestsDisabled {
    $RegPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds"
    return (Get-ItemProperty -Path $RegPath -Name ShellFeedsTaskbarViewMode -ErrorAction SilentlyContinue).ShellFeedsTaskbarViewMode -eq 2
}

# Function to disable Widgets on the taskbar
function Disable-Widgets {
    # Disable the Widgets icon on the taskbar
    $WidgetsPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    if (-not (Test-Path $WidgetsPath)) {
        New-Item -Path $WidgetsPath -Force | Out-Null
    }
    Set-ItemProperty -Path $WidgetsPath -Name TaskbarDa -Value 0 -Type DWord

    # Disable the Widgets service if it's running
    $WidgetsService = Get-Service -Name "Widgets" -ErrorAction SilentlyContinue
    if ($WidgetsService -and $WidgetsService.Status -eq "Running") {
        Stop-Service -Name "Widgets" -Force -ErrorAction SilentlyContinue
        Set-Service -Name "Widgets" -StartupType Disabled -ErrorAction SilentlyContinue
    }

    Write-Verbose "Widgets on the taskbar have been disabled."
}

# Function to check if Widgets are disabled
function Test-WidgetsDisabled {
    $WidgetsPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    return (Get-ItemProperty -Path $WidgetsPath -Name TaskbarDa -ErrorAction SilentlyContinue).TaskbarDa -eq 0
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

# Function to check if Python is already in PATH
function Test-PythonInPath {
    return [bool](Get-Command python -ErrorAction SilentlyContinue)
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
    Write-Verbose "Downloaded $FileName to $DestinationPath"

    # Download hash file
    Invoke-WebRequest -Uri $HashURL -OutFile $HashFile
    Write-Verbose "Downloaded SHA256 hash file for $FileName to $HashFile"

    # Check hash
    $LocalHash = (Get-FileHash $DestinationPath -Algorithm SHA256).Hash.ToLower()
    $RemoteHash = (Get-Content $HashFile -Raw).Split(" ")[0].ToLower()

    if ($LocalHash -ne $RemoteHash) {
        Write-Error "Hash check failed for $FileName. Local hash: $LocalHash, Remote hash: $RemoteHash"
        Remove-Item $DestinationPath, $HashFile
        return $false
    }
    Write-Verbose "Hash check successful for $FileName."
    return $true
}

# Function to check if Kubernetes utilities are already in downloads
function Test-KubeUtilsDownloaded {
    $KubeUtils = @("kubeadm.exe", "kubectl-convert.exe", "kube-log-runner.exe", "kubectl.exe")
    $downloadPath = "$env:USERPROFILE\Downloads"
    return $KubeUtils | ForEach-Object { Test-Path -Path "$downloadPath\$_" } | Where-Object { $_ -eq $false } | Measure-Object | Select-Object -ExpandProperty Count -eq 0
}

# Function to add kubectl autocomplete
function Add-KubectlAutocomplete {
    $CompletionScript = kubectl completion powershell
    $CompletionScript | Out-String | Invoke-Expression
    
    # Ensure the profile directory exists
    $profileDir = Split-Path $PROFILE -Parent
    if (-not (Test-Path $profileDir)) {
        New-Item -ItemType Directory -Path $profileDir | Out-Null
    }

    # Create profile if it does not exist, then add content
    if (-not (Test-Path $PROFILE)) {
        New-Item -ItemType File -Path $PROFILE -Force | Out-Null
    }

    Add-Content $PROFILE "`n$CompletionScript"
    Write-Verbose "kubectl autocompletion added to PowerShell profile."
}

# Main execution
try {
    # Get TOPO number from user file
    $topoNumber = Get-UserTopoNumber
    if ($null -eq $topoNumber) {
        Write-Error "Failed to retrieve TOPO number from user file. Script cannot continue."
        return
    }

    # Create Scripts directory
    New-ScriptsDirectory
    
    # Download EDU-XSIAM-Engineer-Example.py to Scripts directory
    $scriptURL = "https://raw.githubusercontent.com/norsemen-local/lab-builder/refs/heads/main/EDU-XSIAM-Engineer-Example.py"
    $scriptDestination = "$env:USERPROFILE\Desktop\Scripts\EDU-XSIAM-Engineer-Example.py"
    if (-not (Test-Path $scriptDestination)) {
        Download-Script -URL $scriptURL -Destination $scriptDestination
    } else {
        Write-Verbose "EDU-XSIAM-Engineer-Example.py already exists, skipping download."
    }

    # Disable News and Interests if not already disabled
    if (-not (Test-NewsAndInterestsDisabled)) {
        Disable-NewsAndInterests
    } else {
        Write-Verbose "News and Interests already disabled."
    }

    # Disable Widgets on taskbar if not already disabled
    if (-not (Test-WidgetsDisabled)) {
        Disable-Widgets
    } else {
        Write-Verbose "Widgets already disabled on the taskbar."
    }

    # Add Python to PATH if not already in PATH
    if (-not (Test-PythonInPath)) {
        $PythonDir = Find-PythonPath
        if ($PythonDir) {
            $OldPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
            if (-not ($OldPath -split ';' | Where-Object { $_ -eq $PythonDir })) {
                $NewPath = "$OldPath;$PythonDir"
                [Environment]::SetEnvironmentVariable("Path", $NewPath, "Machine")
                $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
                Write-Verbose "Added $PythonDir to system PATH."
            }
        }
    } else {
        Write-Verbose "Python is already in the system PATH."
    }

    # Download and setup Kubernetes utilities if not in Downloads
    if (-not (Test-KubeUtilsDownloaded)) {
        $KubeUtils = @("kubeadm.exe", "kubectl-convert.exe", "kube-log-runner.exe", "kubectl.exe")
        foreach ($util in $KubeUtils) {
            if (DownloadAndCheckFile -FileName $util -FileType "exe") {
                # Move the utility to C:\Windows\System32
                $SysPath = "C:\Windows\System32"
                $UtilPath = "$env:USERPROFILE\Downloads\$util"
                Move-Item -Path $UtilPath -Destination $SysPath -Force
                Write-Verbose "$util moved to $SysPath"
            }
        }

        # Add to system PATH (in case it's not already there or for new files)
        $OldPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
        $NewPath = "$OldPath;$SysPath"
        [Environment]::SetEnvironmentVariable("Path", $NewPath, "Machine")
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
        Write-Verbose "Utilities added to system PATH."
    } else {
        Write-Verbose "Kubernetes utilities already downloaded, skipping setup."
    }

    # Add kubectl autocomplete (assuming this can be added multiple times without issues)
    Add-KubectlAutocomplete

    # Define and append server information with TOPO number
    $serverInfo = @(
        "Windows Server Information:",
        "Name: dc-$topoNumber",
        "IP: 192.168.3.65",
        "Username: lab-user",
        "Password: Paloalto1!",
        "AD Username: ad-$topoNumber\Administrator",
        "AD Password: Paloalto1!",
        "FQDN: dc-$topoNumber.ad-$topoNumber.local",
        "",
        "Linux Server Information:",
        "Name: ubuntu",
        "IP: 192.168.3.66",
        "Username: lab-user",
        "Password: Paloalto1!",
        "CDR POD Access: sudo microk8s kubectl exec -it alpine-cdr-1 -- sh",
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

    # Restart explorer to apply all changes to the taskbar
    Stop-Process -Name explorer -Force

    Write-Host "`nLab setup completed successfully. Server information appended to lab-build.txt."
}
catch {
    Write-Error "An error occurred during setup: $_"
}