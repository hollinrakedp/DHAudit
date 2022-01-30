function Invoke-LogRotate {
    <#
    .SYNOPSIS
    Rotate a Windows event log by creating a backup and clearing the log.

    .DESCRIPTION
    This function will rotate the specified Windows Event log(s). It creates a backup of the existing events by saving the log to the specified location. Once the backup is created the log(s) will be cleared. If it cannot create a backup of an event log, the log will not be cleared. If the log file already exists in the backup path, the backup will fail and the log will not be cleared. The name of each log backed up is in the following format: yyyyMMdd_COMPUTERNAME_LogName.evtx

    It is also possible to run this function as a scheduled task. To create this scheduled task, use the '-RegisterScheduledTask' parameter to create the scheduled task. The scheduled task will run weekly on Mondays at 1am as SYSTEM. Ensure the module containing this function is located in the PSModulePath or the task will fail to run properly.
    
    If you want to remove the scheduled task, use the '-UnregisterScheduledTask' parameter.

    .NOTES
    Name         - Invoke-LogRotate
    Version      - 0.8
    Author       - Darren Hollinrake
    Date Created - 2021-12-28
    Date Updated - 2022-01-28

    .PARAMETER LogName
    Specify the name of one or more logs to rotate. If this parameter is not specified, it will default to rotating the following logs: Application, Security, and System

    .PARAMETER BackupPath
    The location where the logs will be saved. A subfolder with the current date (yyyyMMdd) will be created within this location. If this parameter is not specified, it will default to the following path: C:\Audit\Archive

    .PARAMETER NoBackup
    If you specify this switch, the logs specified will be cleared WITHOUT being backed up first.

    .PARAMETER RegisterScheduledTask
    Register a scheduled task to rotate the logs weekly on Mondays at 1am.

    .PARAMETER UnregisterScheduledTask
    Unregisters the scheduled task for rotating the logs.

    .EXAMPLE
    Invoke-LogRotate

    Rotates the Application, Security, and System logs. They will be placed in a subfolder of "C:\Audit\Archive" with the current date (yyyyMMdd).

    .EXAMPLE
    Invoke-LogRotate -LogName 'Security' -BackupPath "C:\Logs"

    Rotates the Security log. The log will be placed in "C:\Logs\yyyyMMdd".

    #>

    [CmdletBinding(DefaultParameterSetName = "LogRotate")]

    Param(
        [Parameter(ParameterSetName = 'LogRotate',
            ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName = 'LogClear',
            ValueFromPipelineByPropertyName)]
        [Parameter(
            ParameterSetName = 'AddScheduledTask',
            ValueFromPipelineByPropertyName,
            ValueFromPipeline)]
        [string[]]$LogName = @("Application", "Security", "System"),
        [Parameter(ParameterSetName = 'LogRotate',
            ValueFromPipelineByPropertyName)]
        [string]$BackupPath = "C:\Audit\Archive",
        [Parameter(ParameterSetName = 'LogClear',
            ValueFromPipelineByPropertyName)]
        [switch]$NoBackup,
        [Parameter(ParameterSetName = 'AddScheduledTask',
            ValueFromPipelineByPropertyName)]
        [switch]$RegisterScheduledTask,
        [Parameter(ParameterSetName = 'RemoveScheduledTask',
            ValueFromPipelineByPropertyName)]
        [switch]$UnregisterScheduledTask
    )

    $TaskName = "Log Rotate"
    $TaskPath = "\Audit"

    switch ($PsCmdlet.ParameterSetName) {
        LogRotate {
            Write-Verbose "Clearing the following $($LogName.Count) log(s): $($LogName -join ', ' | Out-String)"
            foreach ($Log in $LogName) {
                if ([System.Diagnostics.EventLog]::Exists("$Log")) {
                    switch ($NoBackup) {
                        True {
                            wevtutil Clear-log $Log
                        }
                        False {
                            $SubLogPath = Join-Path -Path $BackupPath -ChildPath $(Get-Date -Format yyyyMMdd)
                            If (!(Test-Path "$SubLogPath")) {
                                New-Item -ItemType Directory -Force -Path "$SubLogPath" | Out-Null
                            }
                            $BackupLogPath = Join-Path -Path $SubLogPath -ChildPath "$(Get-Date -Format yyyyMMdd)_$($env:COMPUTERNAME)_$Log.evtx"
                            wevtutil Clear-log $Log `/bu:"$BackupLogPath" 
                        }
                    }
                }
                else {
                    Write-Warning "No log with name `"$Log`" exists; Skipping."
                }
            }
        }

        AddScheduledTask {
            $LogName = "`"$($LogName -join '","')`""
            $Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -NoProfile -Command Invoke-LogRotate -LogName $LogName -BackupPath `"$BackupPath`""
            $Trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 1am
            $Principal = New-ScheduledTaskPrincipal "NT AUTHORITY\SYSTEM" -RunLevel Highest
            $Settings = New-ScheduledTaskSettingsSet
            $Description = "Clears the event logs on the PC after saving a backup to a subfolder in `'$BackupPath`' folder."
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