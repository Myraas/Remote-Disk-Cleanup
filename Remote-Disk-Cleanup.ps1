#Requires -RunAsAdministrator

# Global flag to control local run
$global:LocalRun = $true

# Global flag to control verbose mode
$global:EnableVerbose = $false

# Global flag to control WMI repair
$global:RepairWMI = $true

# Set verbosity based on the global flag
if ($EnableVerbose) {
    $VerbosePreference = "Continue"
} else {
    $VerbosePreference = "SilentlyContinue"
}

# Set registry keys to check all Disk Cleanup boxes
$SageSet = "StateFlags0099"
$StateFlags = "Stateflags0099"
$Base = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\"
$VolCaches = Get-ChildItem $Base

$Locations = @(
    "Active Setup Temp Folders",
    "BranchCache",
    "Downloaded Program Files",
    "GameNewsFiles",
    "GameStatisticsFiles",
    "GameUpdateFiles",
    "Internet Cache Files",
    "Memory Dump Files",
    "Offline Pages Files",
    "Old ChkDsk Files",
    "Previous Installations",
    #"Recycle Bin",
    "Service Pack Cleanup",
    "Setup Log Files",
    "System error memory dump files",
    "System error minidump files",
    "Temporary Files",
    "Temporary Setup Files",
    "Temporary Sync Files",
    "Thumbnail Cache",
    "Update Cleanup",
    "Upgrade Discarded Files",
    "User file versions",
    "Windows Defender",
    "Windows Error Reporting Archive Files",
    "Windows Error Reporting Queue Files",
    "Windows Error Reporting System Archive Files",
    "Windows Error Reporting System Queue Files",
    "Windows ESD installation files",
    "Windows Upgrade Log Files"
)

Function Get-RecycleBin {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        $ComputerOBJ,
        [int]$RetentionTime = 3
    )
    Write-Host "Emptying Recycle bin items older than $RetentionTime days" -ForegroundColor Yellow
    If ($ComputerOBJ.PSRemoting -eq $true) {
        $Result = Invoke-Command -ComputerName $ComputerOBJ.ComputerName -ScriptBlock {
            Try {
                $Shell = New-Object -ComObject Shell.Application
                $Recycler = $Shell.NameSpace(0xa)
                $Recycler.Items()

                foreach ($item in $Recycler.Items()) {
                    $DeletedDate = $Recycler.GetDetailsOf($item, 2) -replace "\u200f|\u200e", "" # Invisible Unicode Characters
                    $DeletedDatetime = Get-Date $DeletedDate
                    [int]$DeletedDays = (New-TimeSpan -Start $DeletedDatetime -End $(Get-Date)).Days

                    If ($DeletedDays -ge $RetentionTime) {
                        Remove-Item -Path $item.Path -Confirm:$false -Force -Recurse
                    }
                }
            } Catch {
                $RecyclerError = $true
            } Finally {
                If ($RecyclerError -eq $false) {
                    Write-output $true
                } Else {
                    Write-Output $false
                }
            }
        } -Credential $ComputerOBJ.Credential

        If ($Result -eq $true) {
            Write-Host "All recycle bin items older than $RetentionTime days were deleted" -ForegroundColor Green
        } Else {
            Write-Host "Unable to delete some items in the Recycle Bin." -ForegroundColor Red
        }
    } Else {
        Try {
            $Shell = New-Object -ComObject Shell.Application
            $Recycler = $Shell.NameSpace(0xa)
            $Recycler.Items()

            foreach ($item in $Recycler.Items()) {
                $DeletedDate = $Recycler.GetDetailsOf($item, 2) -replace "\u200f|\u200e", "" # Invisible Unicode Characters
                $DeletedDatetime = Get-Date $DeletedDate
                [int]$DeletedDays = (New-TimeSpan -Start $DeletedDatetime -End $(Get-Date)).Days

                If ($DeletedDays -ge $RetentionTime) {
                    Remove-Item -Path $item.Path -Confirm:$false -Force -Recurse
                }
            }
        } Catch {
            $RecyclerError = $true
        } Finally {
            If ($RecyclerError -eq $true) {
                Write-Host "Unable to delete some items in the Recycle Bin." -ForegroundColor Red
            } Else {
                Write-Host "All recycle bin items older than $RetentionTime days were deleted" -ForegroundColor Green
            }
        }
    }
}

Function Clean-Path {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [Parameter(Mandatory=$true)]
        $ComputerOBJ
    )
    Write-Host "`t...Cleaning $Path"
    If ($ComputerOBJ.PSRemoting -eq $true) {
        Invoke-Command -ComputerName $ComputerOBJ.ComputerName -ScriptBlock {
            If (Test-Path $Using:Path) {
                Foreach ($Item in $(Get-ChildItem -Path $Using:Path -Recurse)) {
                    Try {
                        Remove-item -Path $item.FullName -Confirm:$false -Recurse -ErrorAction Stop
                    } Catch {
                        if ($global:EnableVerbose) {
                            Write-Verbose "$($Item.path) - $($_.Exception.Message)"
                        }
                    }
                }
            }
        } -Credential $ComputerOBJ.Credential
    } Else {
        If (Test-Path $Path) {
            Foreach ($Item in $(Get-ChildItem -Path $Path -Recurse)) {
                Try {
                    Remove-item -Path $item.FullName -Confirm:$false -Recurse -ErrorAction Stop
                } Catch {
                    if ($global:EnableVerbose) {
                        Write-Verbose "$($Item.path) - $($_.Exception.Message)"
                    }
                }
            }
        }
    }
}

Function Get-OrigFreeSpace {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        $ComputerOBJ
    )
    Try {
        $RawFreeSpace = (Get-WmiObject Win32_logicaldisk -ComputerName $ComputerOBJ.ComputerName -Credential $ComputerOBJ.Credential -ErrorAction Stop | Where-Object { $_.DeviceID -eq 'C:' }).freespace
        $FreeSpaceGB = [decimal]("{0:N2}" -f($RawFreeSpace / 1GB))
        Write-Host "Current Free Space on the OS Drive : $FreeSpaceGB GB" -ForegroundColor Magenta
    } Catch {
        $FreeSpaceGB = $false
        Write-Host "Unable to retrieve free space from OS drive." -ForegroundColor Red
    } Finally {
        $ComputerOBJ | Add-Member -MemberType NoteProperty -Name OrigFreeSpace -Value $FreeSpaceGB
        Write-output $ComputerOBJ
    }
}

Function Get-FinalFreeSpace {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        $ComputerOBJ
    )
    Try {
        $RawFreeSpace = (Get-WmiObject Win32_logicaldisk -ComputerName $ComputerOBJ.ComputerName -Credential $ComputerOBJ.Credential -ErrorAction Stop | Where-Object { $_.DeviceID -eq 'C:' }).freespace
        $FreeSpaceGB = [decimal]("{0:N2}" -f($RawFreeSpace / 1GB))
        Write-Host "Final Free Space on the OS Drive : $FreeSpaceGB GB" -ForegroundColor Magenta
    } Catch {
        $FreeSpaceGB = $false
        Write-Host "Unable to retrieve free space from OS drive." -ForegroundColor Red
    } Finally {
        $ComputerOBJ | Add-Member -MemberType NoteProperty -Name FinalFreeSpace -Value $FreeSpaceGB
        Write-output $ComputerOBJ
    }
}

Function Get-ComputerName {
    Param (
        [switch]$LocalRun
    )
    if ($LocalRun) {
        $obj = New-Object PSObject -Property @{
            ComputerName = $env:COMPUTERNAME
            Remote = $false
        }
    } Else {
        Write-Host "Please enter the computer name to connect to or just hit enter for localhost" -ForegroundColor Yellow
        $ComputerName = Read-Host

        if ($ComputerName -eq '' -or $ComputerName -eq $null) {
            $obj = New-Object PSObject -Property @{
                ComputerName = $env:COMPUTERNAME
                Remote = $false
            }
        } Else {
            $obj = New-Object PSObject -Property @{
                ComputerName = $ComputerName
                Remote = $true
            }
        }
    }
    Write-output $obj
}

Function Test-PSRemoting {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        $ComputerOBJ
    )
    Write-Host "Please enter your credentials for the remote machine." -ForegroundColor Yellow
    $ComputerOBJ | Add-Member NoteProperty -Name Credential -Value (Get-Credential)

    $RemoteHostname = Invoke-Command -ComputerName $ComputerOBJ.ComputerName -ScriptBlock { hostname } -Credential $ComputerOBJ.Credential -ErrorAction 'SilentlyContinue'

    If ($RemoteHostname -eq $ComputerOBJ.ComputerName) {
        Write-Host "PowerShell Remoting was successful" -ForegroundColor Green
        $ComputerOBJ | Add-Member NoteProperty -Name PSRemoting -Value $true
    } Else {
        Write-Host "PowerShell Remoting FAILED. Press enter to exit script." -ForegroundColor Red
        $ComputerOBJ | Add-Member NoteProperty -Name PSRemoting -Value $false
    }
    Write-output $ComputerOBJ
}

Function Run-CleanMGR {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        $ComputerOBJ
    )
    If ($ComputerOBJ.PSRemoting -eq $true) {
        Write-Host "Attempting to run Windows Disk Cleanup with parameters..." -ForegroundColor Yellow
        Write-Host "`tApplying $SageSet parameters to registry path:"
        Write-Host "`t$Base"
        $CleanMGR = Invoke-Command -ComputerName $ComputerOBJ.ComputerName -ScriptBlock {
            $ErrorActionPreference = 'Stop'
            Try {
                # Set Sageset99/Stateflag0099 reg keys to 1 for a blank slate.
                foreach ($VC in $VolCaches) {
                    New-ItemProperty -Path "$($VC.PSPath)" -Name $StateFlags -Value 1 -Type DWORD -Force | Out-Null
                }
                ForEach ($Location in $Locations) {
                    Set-ItemProperty -Path $($Base + $Location) -Name $SageSet -Type DWORD -Value 2 -ea SilentlyContinue | Out-Null
                }
                # Convert the Sageset number previously defined and run the Disk Cleanup process with configured parameters.
                $Args = "/sagerun:$([string]([int]$SageSet.Substring($SageSet.Length - 4)))"
                Start-Process -Wait "$env:SystemRoot\System32\cleanmgr.exe" -ArgumentList $Args -WindowStyle Hidden
                # Set Sageset99/Stateflag0099 reg keys back to 1 for a blank slate.
                foreach ($VC in $VolCaches) {
                    New-ItemProperty -Path "$($VC.PSPath)" -Name $StateFlags -Value 1 -Type DWORD -Force | Out-Null
                }
                $ErrorActionPreference = 'SilentlyContinue'
            } Catch {
                $ErrorActionPreference = 'SilentlyContinue'
            }
        } -Credential $ComputerOBJ.Credential

        If ($CleanMGR -eq $true) {
            ForEach ($Location in $Locations) {
                Write-Host "`t...Cleaning $Location"
            }
            Write-Host "Windows Disk Cleanup has been run successfully." -ForegroundColor Green
        } Else {
            Write-Host "Cleanmgr is not installed!" -ForegroundColor Red
        }
    } Else {
        Write-Host "Attempting to run Windows Disk Cleanup with parameters..." -ForegroundColor Yellow
        Write-Host "`tApplying $SageSet parameters to registry path:"
        Write-Host "`t$Base"
        $ErrorActionPreference = 'Stop'
        Try {
            # Set Sageset99/Stateflag0099 reg keys to 1 for a blank slate.
            foreach ($VC in $VolCaches) {
                New-ItemProperty -Path "$($VC.PSPath)" -Name $StateFlags -Value 1 -Type DWORD -Force | Out-Null
            }
            ForEach ($Location in $Locations) {
                Set-ItemProperty -Path $($Base + $Location) -Name $SageSet -Type DWORD -Value 2 -ea SilentlyContinue | Out-Null
            }
            # Convert the Sageset number previously defined and run the Disk Cleanup process with configured parameters.
            $Args = "/sagerun:$([string]([int]$SageSet.Substring($SageSet.Length - 4)))"
            Start-Process -Wait "$env:SystemRoot\System32\cleanmgr.exe" -ArgumentList $Args -WindowStyle Hidden
            # Set Sageset99/Stateflag0099 reg keys back to 1 for a blank slate.
            foreach ($VC in $VolCaches) {
                New-ItemProperty -Path "$($VC.PSPath)" -Name $StateFlags -Value 1 -Type DWORD -Force | Out-Null
            }
            $ErrorActionPreference = 'SilentlyContinue'
            ForEach ($Location in $Locations) {
                Write-Host "`t...Cleaning $Location"
            }
            Write-Host "Windows Disk Cleanup has been run successfully." -ForegroundColor Green
        } Catch {
            Write-Host "Cleanmgr is not installed!" -ForegroundColor Red
        }
        $ErrorActionPreference = 'SilentlyContinue'
    }
}

Function Erase-IExplorerHistory {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        $ComputerOBJ
    )
    If ($ComputerOBJ.PSRemoting -eq $true) {
        Write-Host "Attempting to erase Internet Explorer temp data" -ForegroundColor Yellow
        $CleanIExplorer = Invoke-Command -ComputerName $ComputerOBJ.ComputerName -ScriptBlock {
            $ErrorActionPreference = 'Stop'
            Try {
                Start-Process -FilePath rundll32.exe -ArgumentList 'inetcpl.cpl,ClearMyTracksByProcess 4351' -Wait -NoNewWindow
                $ErrorActionPreference = 'SilentlyContinue'
            } Catch {
                $ErrorActionPreference = 'SilentlyContinue'
            }
        } -Credential $ComputerOBJ.Credential

        If ($CleanIExplorer -eq $true) {
            Write-Host "Internet Explorer temp data has been successfully erased" -ForegroundColor Green
        } Else {
            Write-Host "Failed to erase Internet Explorer temp data" -ForegroundColor Red
        }
    } Else {
        Write-Host "Attempting to erase Internet Explorer temp data" -ForegroundColor Yellow
        $ErrorActionPreference = 'Stop'
        Try {
            Start-Process -FilePath rundll32.exe -ArgumentList 'inetcpl.cpl,ClearMyTracksByProcess 4351' -Wait -NoNewWindow
            Write-Host "Internet Explorer temp data has been successfully erased" -ForegroundColor Green
        } Catch {
            Write-Host "Failed to erase Internet Explorer temp data" -ForegroundColor Red
        }
        $ErrorActionPreference = 'SilentlyContinue'
    }
}

Function Run-DISM {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        $ComputerOBJ
    )
    If ($ComputerOBJ.PSRemoting -eq $true) {
        Write-Host "Running DISM to clean old service pack files" -ForegroundColor Yellow
        $DISM = Invoke-Command -ComputerName $ComputerOBJ.ComputerName -ScriptBlock {
            $ErrorActionPreference = 'Stop'
            Try {
                $DISMResult = dism.exe /online /cleanup-Image /spsuperseded
                $ErrorActionPreference = 'SilentlyContinue'
                Write-Output $DISMResult
            } Catch {
                $ErrorActionPreference = 'SilentlyContinue'
                Write-Output $false
            }
        } -Credential $ComputerOBJ.Credential

        If ($DISM -match 'The operation completed successfully') {
            Write-Host "DISM completed successfully." -ForegroundColor Green
        } Else {
            Write-Host "Unable to clean old Service Pack Files." -ForegroundColor Red
        }
    } Else {
        Write-Host "Running DISM to clean old service pack files" -ForegroundColor Yellow
        $ErrorActionPreference = 'Stop'
        Try {
            $DISMResult = dism.exe /online /cleanup-Image /spsuperseded
            $ErrorActionPreference = 'SilentlyContinue'
        } Catch {
            $ErrorActionPreference = 'SilentlyContinue'
            $DISMResult = $false
        }
        $ErrorActionPreference = 'SilentlyContinue'
        If ($DISMResult -match 'The operation completed successfully') {
            Write-Host "DISM completed successfully." -ForegroundColor Green
        } Else {
            Write-Host "Unable to clean old Service Pack Files." -ForegroundColor Red
        }
    }
}

Function Repair-WMIRepository {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        $ComputerOBJ
    )
    If ($ComputerOBJ.PSRemoting -eq $true) {
        Write-Host "Attempting to repair WMI repository remotely..." -ForegroundColor Yellow
        Invoke-Command -ComputerName $ComputerOBJ.ComputerName -ScriptBlock {
            $ErrorActionPreference = 'Stop'
            Try {
                cmd.exe /c "Winmgmt /salvagerepository"
                $ErrorActionPreference = 'SilentlyContinue'
            } Catch {
                $ErrorActionPreference = 'SilentlyContinue'
            }
        } -Credential $ComputerOBJ.Credential
        Write-Host "WMI repository repair command executed on remote machine." -ForegroundColor Green
    } Else {
        Write-Host "Attempting to repair WMI repository locally..." -ForegroundColor Yellow
        $ErrorActionPreference = 'Stop'
        Try {
            cmd.exe /c "Winmgmt /salvagerepository"
            Write-Host "WMI repository repaired successfully." -ForegroundColor Green
        } Catch {
            Write-Host "Failed to repair WMI repository." -ForegroundColor Red
        }
        $ErrorActionPreference = 'SilentlyContinue'
    }
}

# Main script execution
Clear-Host
Write-Host "** This tool will attempt to erase temp files across all user profiles. Please use with caution. **" -ForegroundColor Yellow
Write-Host ""
$ComputerOBJ = Get-ComputerName -LocalRun:$LocalRun

# Auto-confirm if LocalRun is true, else prompt for confirmation
if ($LocalRun) {
    Write-Host "Auto-confirmed: You have entered $ComputerOBJ."
} Else {
    Write-Host "You have entered $ComputerOBJ. Is this correct?"
    Pause
}

Write-Host ""

try {
    Stop-Transcript -ErrorAction Stop
} catch {

}

# Start logging
$Timestamp = Get-Date -Format "yyyy-MM-dd_THHmmss"
Write-Host "Starting transcript logging to C:\temp\$($ComputerOBJ.ComputerName)-CleanupLogs_$Timestamp.txt"
Start-Transcript -Path "C:\temp\$($ComputerOBJ.ComputerName)-CleanupLogs_$Timestamp.txt"
[System.DateTime]::Now
Write-Host ""

Write-Host "*******************************************************************************************"
If ($ComputerOBJ.Remote -eq $true) {
    $ComputerOBJ = Test-PSRemoting -ComputerOBJ $ComputerOBJ
    If ($ComputerOBJ.PSRemoting -eq $false) {
        Read-Host
        exit
    }
}

$ComputerOBJ = Get-OrigFreeSpace -ComputerOBJ $ComputerOBJ

If ($ComputerOBJ.OrigFreeSpace -eq $false) {
    Read-Host
    exit
}
Write-Host "*******************************************************************************************"
Write-Host ""

#=================================================================================================

Write-Host "Cleaning temp directories across all user profiles" -ForegroundColor Yellow

#Clean-Path -Path 'C:\Temp\*' -Verbose:$EnableVerbose -ComputerOBJ $ComputerOBJ
Clean-Path -Path 'C:\Windows\Temp\*' -Verbose:$EnableVerbose -ComputerOBJ $ComputerOBJ
Clean-Path -Path 'C:\Users\*\Documents\*tmp' -Verbose:$EnableVerbose -ComputerOBJ $ComputerOBJ
Clean-Path -Path 'C:\Documents and Settings\*\Local Settings\Temp\*' -Verbose:$EnableVerbose -ComputerOBJ $ComputerOBJ
Clean-Path -Path 'C:\Users\*\Appdata\Local\Temp\*' -Verbose:$EnableVerbose -ComputerOBJ $ComputerOBJ
Clean-Path -Path 'C:\Users\*\AppData\Local\Microsoft\Windows\Temporary Internet Files\*' -Verbose:$EnableVerbose -ComputerOBJ $ComputerOBJ
Clean-Path -Path 'C:\Users\*\AppData\Roaming\Microsoft\Windows\Cookies\*' -Verbose:$EnableVerbose -ComputerOBJ $ComputerOBJ

## Optional paths. Clean at your own risk.
#Clean-Path -Path 'C:\ServiceProfiles\LocalService\AppData\Local\Temp\*' -Verbose:$EnableVerbose -ComputerOBJ $ComputerOBJ
#Clean-Path -Path 'C:\Windows\Prefetch' -Verbose:$EnableVerbose -ComputerOBJ $ComputerOBJ
#Clean-Path -Path 'C:\Users\*\AppData\Local\Microsoft\Windows\INetCache' -Verbose:$EnableVerbose -ComputerOBJ $ComputerOBJ
#Clean-Path -Path 'C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent' -Verbose:$EnableVerbose -ComputerOBJ $ComputerOBJ
#Clean-Path -Path 'C:\AppData\Roaming\Microsoft\Windows\Recent' -Verbose:$EnableVerbose -ComputerOBJ $ComputerOBJ
#Clean-Path -Path 'C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Cache' -Verbose:$EnableVerbose -ComputerOBJ $ComputerOBJ
#Clean-Path -Path 'C:\Users\*\AppData\Local\Mozilla\Firefox\Profiles\*.default' -Verbose:$EnableVerbose -ComputerOBJ $ComputerOBJ
#Clean-Path -Path 'C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*.default' -Verbose:$EnableVerbose -ComputerOBJ $ComputerOBJ
#Clean-Path -Path 'C:\ProgramData\Microsoft\Windows\WER\ReportArchive' -Verbose:$EnableVerbose -ComputerOBJ $ComputerOBJ
#Clean-Path -Path 'C:\ProgramData\Microsoft\Windows\WER\ReportQueue' -Verbose:$EnableVerbose -ComputerOBJ $ComputerOBJ

Write-Host "All temp paths have been cleaned" -ForegroundColor Green
Write-Host ""

#=================================================================================================

Run-CleanMGR -ComputerOBJ $ComputerOBJ
Write-Host ""
#Erase-IExplorerHistory -ComputerOBJ $ComputerOBJ
Write-Host ""
Run-DISM -ComputerOBJ $ComputerOBJ
Write-Host ""
Get-RecycleBin -ComputerOBJ $ComputerOBJ
Write-Host ""

# Optionally repair WMI repository if needed
if ($RepairWMI) {
    Repair-WMIRepository -ComputerOBJ $ComputerOBJ
    Write-Host ""
}

Write-Host "*******************************************************************************************"
$ComputerOBJ = Get-FinalFreeSpace -ComputerOBJ $ComputerOBJ
$SpaceRecovered = $($ComputerOBJ.FinalFreeSpace) - $($ComputerOBJ.OrigFreeSpace)

If ($SpaceRecovered -lt 0) {
    Write-Host "Less than a gigabyte of free space was recovered." -ForegroundColor Magenta
} ElseIf ($SpaceRecovered -eq 0) {
    Write-Host "No space was recovered" -ForegroundColor Magenta
} Else {
    Write-Host "Free space recovered: $SpaceRecovered GB" -ForegroundColor Magenta
}
Write-Host "*******************************************************************************************"

Write-Host ""
Stop-Transcript
