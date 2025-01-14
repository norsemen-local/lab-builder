# Ensure script runs with administrative privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
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
        exit
    }
    Write-Host "Hash check successful for $FileName."
}

# Function to add kubectl autocomplete
function Add-KubectlAutocomplete {
    $CompletionScript = kubectl completion powershell
    $CompletionScript | Out-String | Invoke-Expression
    
    # Save to PowerShell profile
    Add-Content $PROFILE "`n$kCompletionScript"
    Write-Host "kubectl autocompletion added to PowerShell profile."
}

# Main script execution
try {
    $KubeUtils = @("kubeadm.exe", "kubectl-convert.exe", "kube-log-runner.exe", "kubectl.exe")

    foreach ($util in $KubeUtils) {
        DownloadAndCheckFile -FileName $util -FileType "exe"
        
        # Move the utility to C:\Windows\System32
        $SysPath = "C:\Windows\System32"
        $UtilPath = "$env:USERPROFILE\Downloads\$util"
        Move-Item -Path $UtilPath -Destination $SysPath -Force
        Write-Host "$util moved to $SysPath"
    }

    # Add to system PATH (in case it's not already there or for new files)
    $OldPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $NewPath = "$OldPath;$SysPath"
    [Environment]::SetEnvironmentVariable("Path", $NewPath, "Machine")
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
    Write-Host "Utilities added to system PATH."

    # Add kubectl autocomplete
    Add-KubectlAutocomplete
}
catch {
    Write-Error "An error occurred: $_"
}