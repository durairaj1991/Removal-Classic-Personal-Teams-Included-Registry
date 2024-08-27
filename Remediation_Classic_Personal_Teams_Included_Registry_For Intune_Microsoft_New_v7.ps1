# Name: Uninstall-TeamsClassic

# This function receives a Path where the Teams classic application was installed. 
# If the application was totally uninstalled before, it is expected the Uninstallation will not occur.

# Ensure classic Teams and personal processes are stopped initially, before removal
$classicTeamsProcesses = Get-Process -Name "Teams" -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "*AppData\Local\Microsoft\Teams*" }
if ($classicTeamsProcesses) {
    Write-Host "Stopping all classic Teams processes" -ForegroundColor Yellow
    $classicTeamsProcesses | Stop-Process -Force
    Write-Host "Stopped all classic Teams processes" -ForegroundColor Green
}

$personalTeamsProcesses = Get-Process -Name "msteams" -ErrorAction SilentlyContinue
if ($personalTeamsProcesses) {
    Write-Host "Stopping Microsoft Teams Personal app process" -ForegroundColor Yellow
    $personalTeamsProcesses | Stop-Process -Force
    Write-Host "Stopped Microsoft Teams Personal app process" -ForegroundColor Green
}

function Uninstall-TeamsClassic($TeamsPath) {
    try {
        $process = Start-Process -FilePath "$TeamsPath\Update.exe" -ArgumentList "--uninstall /s" -PassThru -Wait -ErrorAction STOP

        if ($process.ExitCode -ne 0) {
            Write-Host "Uninstallation failed:."
        }
    } catch {
        Write-Host "Uninstallation failed:."
    }
}

# $AllUsers contains the list of all the users on the server.
# Get all user profiles except system profiles and Public/Default profiles
# Get all user profiles except system profiles, Public/Default profiles, and the currently logged-in user
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

# Loop to uninstall Teams for all the users.
foreach ($User in $AllUsers) {
    Write-Host "Processing user: $($User.Name)"

    # Installation folders
    $localAppData = "$($ENV:SystemDrive)\Users\$($User.Name)\AppData\Local\Microsoft\Teams"
    $programData = "$($env:ProgramData)\$($User.Name)\Microsoft\Teams"

    if (Test-Path "$localAppData\Current\Teams.exe") {
        Write-Host "Uninstalling Classic Teams for user $($User.Name)"
        Uninstall-TeamsClassic -TeamsPath $localAppData
    } elseif (Test-Path "$programData\Current\Teams.exe") {
        Write-Host "Uninstalling Classic Teams for user $($User.Name)"
        Uninstall-TeamsClassic -TeamsPath $programData
    } else {
        Write-Host "Teams installation was not found for user $($User.Name)"
    }
}

# Remove old Teams folders and icons
$TeamsFolder_old = "$($ENV:SystemDrive)\Users\*\AppData\Local\Microsoft\Teams"
$TeamsIcon_old = "$($ENV:SystemDrive)\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Microsoft Teams*.lnk"
Get-Item $TeamsFolder_old | Remove-Item -Force -Recurse
Get-Item $TeamsIcon_old | Remove-Item -Force -Recurse


# Get the current logged-in user's name
$loggedInUser = $env:USERNAME

# Get all user profiles except system profiles, Public/Default profiles, and the currently logged-in user
$AllUsers = Get-ChildItem -Path "$($ENV:SystemDrive)\Users" | Where-Object {
    $_.PSIsContainer -and 
    $_.Name -notlike "Administrator" -and 
    $_.Name -notlike "ITAdmin" -and 
    $_.Name -notlike "IT" -and 
    $_.Name -notlike "Dadmin" -and 
    $_.Name -notlike "Jadmin" -and 
    $_.Name -notlike "Eadmin" -and 
    $_.Name -notlike "Public" -and 
    $_.Name -notlike "Default*" -and
    $_.Name -ne $loggedInUser
}


# Delete the Registry keys fro ANother User Profiles
try {
    # Create a new PSDrive for HKEY_USERS if it doesn't already exist
    if (-not (Get-PSDrive HKU -ErrorAction SilentlyContinue)) {
        New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS
    }

    # $users contains the list of all the users
    $users = $AllUsers

    

       foreach ($user in $users) {
       
        $hiveName = "TEMP_HIVE_$user"

        Write-Host "Loading Hive for $user"

        # 20-second wait before loading the registry hive
        #Write-Host "Start-Sleep -Seconds 20"
        #Start-Sleep -Seconds 20
        

        # Attempt to load the user's registry hive
        try {
            Write-Host " `n`nLoading Registry : ${user}"
            Write-Host "Loading Reg Path $user for at HKU:\$hiveName\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Teams"
            Start-Process -FilePath "reg" -ArgumentList "load", "hku\$hiveName", "C:\Users\$user\NTUSER.DAT" -NoNewWindow -Wait -ErrorAction Stop
        } catch {
            Write-Host "Error: Failed to load hive for ${user}: " -ForegroundColor Red
            continue
        }
        
        # 40-second wait before checking the registry key
        Write-Host "Start-Sleep -Seconds 20"
        Start-Sleep -Seconds 20
        Write-Host "Start-Sleep -Seconds 20"
        Start-Sleep -Seconds 20

         Write-Host " `n"
        # Check for Teams uninstall key and remove it if present
        try {
            $registryPath = "HKU:\$hiveName\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Teams"
            Write-Host "Checking Reg Path $user for at HKU:\$hiveName\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Teams"
            if (Test-Path -Path $registryPath) {
                Write-Host "Found & Removing Reg $user for at HKU:\$hiveName\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Teams"
                Remove-Item -Path $registryPath -Force
                Write-Host "Removed registry key for user $user"
            } else {
                Write-Host " `n"
                Write-Host "Not Found : Reg Path $user for at HKU:\$hiveName\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Teams"
            
            }
        } catch {
            Write-Host "Permission Error or Path Error for ${user}: " -ForegroundColor Red
        }

        # 40-second wait before checking the registry key
        Write-Host "Start-Sleep -Seconds 20"
        Start-Sleep -Seconds 20
        Write-Host "Start-Sleep -Seconds 20"
        Start-Sleep -Seconds 20

        # Attempt to unload the user's registry hive
        try {
            Write-Host " `nUnloading Loading Registry : ${user}"
            Start-Process -FilePath "reg" -ArgumentList "unload", "hku\$hiveName" -NoNewWindow -Wait -ErrorAction Stop
            # 20-second wait after unloading the registry hive
            # 40-second wait before checking the registry key
        Write-Host "Start-Sleep -Seconds 20"
        Start-Sleep -Seconds 20
        } catch {
            Write-Host "Error: Failed to unload hive for ${user}: " -ForegroundColor Red
        }
    }
} catch {
    Write-Host "An unexpected error occurred: " -ForegroundColor Red
}





###########################################################
# Check for Teams Machine-Wide Installer
###########################################################
 Write-Host " `n"
# Remove Teams Machine-Wide Installer
Write-Host "Removing Teams Machine-wide Installer" -ForegroundColor Yellow

$registryPath = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
$MachineWide = Get-ItemProperty -Path $registryPath | Where-Object -Property DisplayName -eq "Teams Machine-Wide Installer"

if ($MachineWide) {
    Write-Host "Found: Teams Machine-Wide Installer installed" -ForegroundColor Green
    Start-Process -FilePath "msiexec.exe" -ArgumentList "/x ""$($MachineWide.PSChildName)"" /qn" -NoNewWindow -Wait
    Write-Host "Waiting 1 minute after uninstallation..." -ForegroundColor Yellow
    Start-Sleep -Seconds 60  # Delay for 60 seconds
    Write-Host "Teams Machine-Wide Installer uninstalled successfully" -ForegroundColor Green
} else {
    Write-Host "Teams Machine-Wide Installer not found" -ForegroundColor Red
}

Write-Host "Checking: Teams Machine-Wide Installer registry entry at HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ForegroundColor Yellow
$MachineWideInstallerRegistryPath = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
$MachineWideInstaller = Get-ItemProperty -Path $MachineWideInstallerRegistryPath | Where-Object { $_.DisplayName -eq "Teams Machine-Wide Installer" }

if ($MachineWideInstaller) {
    Write-Host "Found: Teams Machine-Wide Installer registry entry" -ForegroundColor Green
    $MachineWideInstallerRegistryPath | ForEach-Object {
        Remove-Item -Path $_.PSPath -Recurse -Force
        Write-Host "Removed: Teams Machine-Wide Installer registry entry from $($_.PSPath)" -ForegroundColor Green
    }
} else {
    Write-Host "Not Found: Teams Machine-Wide Installer registry entry" -ForegroundColor Red
}

# Check if Classic Teams is installed from registry
Write-Host "Checking: Classic Teams registry entry at HKLM:\SOFTWARE\Microsoft\Teams" -ForegroundColor Yellow
$ClassicTeamsRegistry = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Teams" -ErrorAction SilentlyContinue

if ($ClassicTeamsRegistry) {
    Write-Host "Found: Classic Teams registry entries at HKLM:\SOFTWARE\Microsoft\Teams" -ForegroundColor Green
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Teams" -Recurse -Force
    Write-Host "Removed: Classic Teams registry entries from HKLM:\SOFTWARE\Microsoft\Teams" -ForegroundColor Green
} else {
    Write-Host "Not Found: Classic Teams registry entries at HKLM:\SOFTWARE\Microsoft\Teams" -ForegroundColor Red
}

# Remove the specified registry key from HKEY_LOCAL_MACHINE
try {
    $regKeyPath = 'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{731F6BAA-A986-45A4-8936-7C3AAAAA760B}'
    
    if (Test-Path -Path $regKeyPath) {
        Remove-Item -Path $regKeyPath -Force
        Write-Host "Removed registry key: $regKeyPath" -ForegroundColor Green
    } else {
        Write-Host "Registry key not found: $regKeyPath" -ForegroundColor Yellow
    }
} catch {
    Write-Output("Something went wrong while removing the registry key: $regKeyPath")
}

# Check if Classic Teams is installed from registry for current user
Write-Host "Checking: Classic Teams registry entry for current user at HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Teams" -ForegroundColor Yellow
$ClassicTeamsCurrentUserRegistry = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Teams" -ErrorAction SilentlyContinue

if ($ClassicTeamsCurrentUserRegistry) {
    Write-Host "Found: Classic Teams registry entry for current user" -ForegroundColor Green
    Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Teams" -Recurse -Force
    Write-Host "Removed: Classic Teams registry entry for current user" -ForegroundColor Green
} else {
    Write-Host "Not Found: Classic Teams registry entry for current user" -ForegroundColor Red
}

Write-Host "All tasks complete."
