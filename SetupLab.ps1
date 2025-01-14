# This script sets up a Windows 11 lab machine.

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

    # Add kubectl autocomplete
    Add-KubectlAutocomplete

    Write-Host "Lab setup completed successfully."
}
catch {
    Write-Error "An error occurred during setup: $_"
}