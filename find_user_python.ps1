# Ensure script runs with administrative privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
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

# Main script execution
try {
    $PythonDir = Find-PythonPath

    if ($PythonDir) {
        # Get current system PATH
        $OldPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
        
        # Check if the path is already in the system PATH to avoid duplicates
        if (-not ($OldPath -split ';' | Where-Object { $_ -eq $PythonDir })) {
            $NewPath = "$OldPath;$PythonDir"
            [Environment]::SetEnvironmentVariable("Path", $NewPath, "Machine")
            
            # Refresh the environment variables for the current session
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
            
            Write-Host "Added $PythonDir to system PATH."
        } else {
            Write-Host "$PythonDir is already in the system PATH."
        }
    }
}
catch {
    Write-Error "An error occurred: $_"
}