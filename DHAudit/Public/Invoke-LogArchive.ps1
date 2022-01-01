function Invoke-LogArchive {
    <#
    .SYNOPSIS
    Copy rotated event logs to an archive location.

    .DESCRIPTION
    This function will archive event logs that have been backed up on the local system to another destination. If a log already exists at the destination, it will not be copied again.

    .NOTES
    Name       : Invoke-LogArchive
    Author     : Darren Hollinrake
    Version    : 0.8
    DateCreated: 2021-12-28
    DateUpdated: 2021-12-31

    .PARAMETER BackupSource
    The location where the backed up logs are saved. These are the logs that will be copied to the destination path.

    .PARAMETER DestinationPath
    The location where the backed up logs will be archived. Within this location a subfolder with the computer name will be created.

    .PARAMETER UserID
    The gMSA User ID that should be used for the scheduled task. Provide it in the format of 'DOMAIN\gmsa.userid$'. The gMSA needs to be configured for use on the computer in question. The account should have at least 'Read' access to the backup path provided and requires at least 'Modify' access for the destination.

    If a non-gMSA account is provided, a password will need to be manually configured for the scheduled task to run.

    .PARAMETER RegisterScheduledTask
    Register a scheduled task to archive the logs automatically.

    .PARAMETER UnregisterScheduledTask
    Unregisters the scheduled task for archiving the logs.

    #>

    [CmdletBinding()]
    param (
        [Parameter(ParameterSetName = 'LogBackup',
            ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName = 'AddScheduledTask',
            ValueFromPipelineByPropertyName)]
        [string]$BackupSource = "C:\Audit\Archive",
        [Parameter(ParameterSetName = 'LogBackup',
            ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName = 'AddScheduledTask',
            ValueFromPipelineByPropertyName,
            Mandatory)]
        [string]$DestinationPath,
        [Parameter(ParameterSetName = 'AddScheduledTask',
            ValueFromPipelineByPropertyName)]
        [string]$UserID,
        [Parameter(ParameterSetName = 'AddScheduledTask',
            ValueFromPipelineByPropertyName)]
        [switch]$RegisterScheduledTask,
        [Parameter(ParameterSetName = 'RemoveScheduledTask',
            ValueFromPipelineByPropertyName)]
        [switch]$UnregisterScheduledTask
    )

    begin {
        $TaskName = "Log Backup"
        $TaskPath = "\Audit"
        $PSDriveName = "Audit"
        $DestinationPSDrive = "$($PSDriveName):\$($env:COMPUTERNAME)"
    }

    process {
        switch ($PsCmdlet.ParameterSetName) {
            LogBackup {
                New-PSDrive -name $PSDriveName -PSProvider FileSystem -Root $DestinationPath
                if (!(Test-Path "$DestinationPSDrive")) {
                    New-Item -ItemType Directory -Path "$DestinationPSDrive" -Force
                }
                else {
                    $Exclude = Get-ChildItem -Path $DestinationPSDrive -File -Recurse
                }

                $BackupFiles = Get-ChildItem "$BackupSource" -Exclude $Exclude
                $BackupFiles | Copy-Item -Destination $DestinationPSDrive -Recurse -Container -Verbose:$VerbosePreference
            }

            AddScheduledTask {
                $Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -NoProfile -Command Invoke-LogBackup"
                $Trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Wednesday -At 5am
                $Principal = New-ScheduledTaskPrincipal -UserID $UserID -LogonType Password
                $Settings = New-ScheduledTaskSettingsSet
                $Description = "Copies rotated logs to a backup location."
                $Task = New-ScheduledTask -Action $Action -Principal $Principal -Trigger $Trigger -Settings $Settings -Description $Description

                Write-Verbose "Registering the scheduled task with name: $TaskName"
                Register-ScheduledTask -TaskName "$TaskName" -TaskPath "$TaskPath" -InputObject $Task
            }

            RemoveScheduledTask {
                Write-Verbose "Unregistering the scheduled task with name: $TaskName"
                Unregister-ScheduledTask -TaskName "$TaskName" -Confirm:$false
            }
        }
    }

    end {
        Remove-PSDrive -Name $PSDriveName
    }
}