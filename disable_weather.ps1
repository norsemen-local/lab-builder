# Ensure script runs with administrative privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
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

# Main execution
try {
    Disable-NewsAndInterests
}
catch {
    Write-Error "An error occurred while disabling News and Interests: $_"
}