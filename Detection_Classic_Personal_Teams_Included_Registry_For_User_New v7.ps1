<#
.SYNOPSIS
This script detects the presence of Microsoft Teams Classic and Personal installations, checks related registry entries for each user profile, and logs the results. It also includes registry checks for the machine-wide installer and personal installations.

.DESCRIPTION
1. Defines functions to ensure the log directory exists and to log output messages.
2. Sets up the log file path with a timestamp for uniqueness.
3. Checks the registry for Teams installations in each user profile by loading the user's registry hive.
4. Checks for Classic and Personal Teams installations by examining common installation paths.
5. Logs the results of the registry and installation checks.
6. Determines and logs the final result based on the detection of Teams installations.
7. Exits with a success or failure code based on the detection outcome.

.LOGGING
Logs are created in the directory "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Teams\" with a timestamp in the filename for uniqueness.

.PARAMETERS
None.

.NOTES
- Ensure the script is run with administrative privileges to perform the required actions.
- The script checks for user profile registries by loading each profile's NTUSER.DAT hive, searches for Teams-related registry entries, and logs the findings.
- It also checks for Teams installations in common directories and logs the presence or absence of the applications.
- Final results are based on the findings and are logged along with exit codes for Intune.
#>


# Function to ensure log directory exists
function Ensure-LogDirectory {
    param (
        [string]$logFilePath
    )

    $logDirectory = Split-Path -Path $logFilePath

    if (-not (Test-Path -Path $logDirectory -PathType Container)) {
        Write-Host "Creating log directory: $logDirectory"
        New-Item -Path $logDirectory -ItemType Directory -Force | Out-Null
    }
}

# Function to log output to file
function Log-Output {
    param (
        [string]$message,
        [string]$logFilePath
    )
    
    $outputLine = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $message"
    Ensure-LogDirectory -logFilePath $logFilePath
    Add-Content -Path $logFilePath -Value $outputLine
}

# Define log file path with date and time
$logFileName = "Detection_Classic_Personal_Teams_Included_Registry_For_User_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$logFilePath = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Teams\$logFileName"

# Function to check registry for Teams
function Check-TeamsRegistry {
    param (
        [string]$hiveName
    )

    $registryPaths = @(
        "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Teams"
    )

    foreach ($path in $registryPaths) {
        $fullPath = "Registry::HKEY_USERS\$hiveName\$path"
        if (Test-Path -Path $fullPath) {
            return $true
        }
    }

    return $false
}

# Get all user profiles except system profiles and Public/Default profiles
$AllUsers = Get-ChildItem -Path "$($ENV:SystemDrive)\Users" | Where-Object {
    $_.PSIsContainer -and 
    $_.Name -notlike "Administrator" -and 
    $_.Name -notlike "ITAdmin" -and 
    $_.Name -notlike "IT" -and 
    $_.Name -notlike "Dadmin" -and 
    $_.Name -notlike "Jadmin" -and 
    $_.Name -notlike "Eadmin" -and 
    $_.Name -notlike "Public" -and 
    $_.Name -notlike "Default*" 
    
}

$registryCheck_OtheruserProfiles_UsingHIVE  = @()

foreach ($userProfile in $AllUsers) {
    $userName = $userProfile.Name
    $userProfilePath = $userProfile.FullName
    $ntUserDatPath = "$userProfilePath\NTUSER.DAT"

    if (Test-Path -Path $ntUserDatPath) {
        $hiveName = "TEMP_HIVE_$userName"
        
        try {
            # Load the user hive
            reg load "HKEY_USERS\$hiveName" "$ntUserDatPath" 2>&1 | Out-Null
            Log-Output "Loaded hive for $userName" $logFilePath
            
            if (Check-TeamsRegistry -hiveName $hiveName) {
                Log-Output "Teams installation found for user: $userName" $logFilePath
                 $registryCheck_OtheruserProfiles_UsingHIVE += "`nHIVE_$userName : SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Teams"
            } else {
                Log-Output "No Teams installation found for user: $userName" $logFilePath
            }
        } catch {
            $errorMessage = $_.Exception.Message
            Log-Output "Failed to load hive for '$userName': $errorMessage" $logFilePath
        } finally {
            # Unload the user hive
            reg unload "HKEY_USERS\$hiveName" 2>&1 | Out-Null
            Log-Output "Unloaded hive for $userName`n" $logFilePath
        }
    } else {
        Log-Output "NTUSER.DAT not found for user: $userName`n" $logFilePath
    }
}

# Check for Teams installation paths
$TeamsClassic = @()
$TeamsPersonal = Get-AppxPackage -Name MicrosoftTeams -AllUsers
$TeamsNew = Get-ChildItem -Path "C:\Program Files\WindowsApps" -Filter "MSTeams_*"

foreach ($User in $AllUsers) {
    $userName = $User.Name
    $localAppData = "$($ENV:SystemDrive)\Users\$userName\AppData\Local\Microsoft\Teams"

    Log-Output "Processing user: $userName" $logFilePath

    if (Test-Path "$localAppData\Current\Teams.exe") {
        $TeamsClassic += "`n$localAppData\Current\Teams.exe"
        Log-Output "Classic Teams found for user: $userName" $logFilePath
    } else {
        Log-Output "Classic Teams not found for user: $userName" $logFilePath
    }
}

# Check if Classic Teams is installed from registry
$ClassicTeamsRegistry = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Teams" -ErrorAction SilentlyContinue

# Check if Classic Teams is installed from registry Current Users
$ClassicTeamsRegistry_CurrentUser = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Teams" -ErrorAction SilentlyContinue

# Check if Teams registry path exists for current user
$ClassicTeamsRegistry_CurrentUserExists = Test-Path -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Teams"

# Check for Teams Machine-Wide Installer
$MachineWideInstallerRegistryPath = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
$MachineWideInstaller = Get-ItemProperty -Path $MachineWideInstallerRegistryPath | Where-Object -Property DisplayName -eq "Teams Machine-Wide Installer"

# Log values of the registry checks
Log-Output "`n`nClassicTeamsRegistry: $($ClassicTeamsRegistry | Out-String)" $logFilePath
Log-Output "`n`nregistryCheck_OtheruserProfiles_UsingHIVE: $($registryCheck_OtheruserProfiles_UsingHIVE | Out-String)" $logFilePath
Log-Output "`n`nClassicTeamsRegistry_CurrentUser: $($ClassicTeamsRegistry_CurrentUser | Out-String)" $logFilePath
Log-Output "`n`nClassicTeamsRegistry_CurrentUserExists: $ClassicTeamsRegistry_CurrentUserExists" $logFilePath
Log-Output "`n`nTeams Machine-Wide Installer: $($MachineWideInstaller | Out-String)" $logFilePath

# Log values of the Teams installation paths
Log-Output "`n`nTeamsClassic: $($TeamsClassic -join ', ')" $logFilePath
Log-Output "`n`nTeamsPersonal: $($TeamsPersonal | Out-String)" $logFilePath
Log-Output "`n`nTeamsNew: $($TeamsNew.FullName -join ', ')" $logFilePath

# Determine result based on detection checks
if (-not $TeamsClassic -and -not $TeamsPersonal -and $TeamsNew -and -not $registryCheck -and -not $ClassicTeamsRegistry -and -not $ClassicTeamsRegistry_CurrentUser -and -not $ClassicTeamsRegistry_CurrentUserExists -and -not $MachineWideInstaller) {
    Log-Output "`n`nClassic and Personal Teams Not Found, ClassicTeamsRegistry not found, or Teams registry path not found for current user.`nNew Teams Only!" $logFilePath
    Log-Output "Detection script completed. Log file saved to: $logFilePath" $logFilePath
    Log-Output "exit 0 # Success exit code for Intune  # Issues Not Detected" $logFilePath
    #exit 0 # Success exit code for Intune
} else {
    Log-Output "`n`nClassic and Personal Teams Found!`nClassicTeamsRegistry found." $logFilePath
    Log-Output "Detection script completed. Log file saved to: $logFilePath" $logFilePath
    Log-Output "exit 1 # Failure exit code for Intune  # Issues Detected" $logFilePath
    #exit 1 # Failure exit code for Intune
}
