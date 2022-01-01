function Invoke-ManualLogArchive {
    <#
    .SYNOPSIS
    Copy rotated event logs to an archive location.

    .DESCRIPTION
    Allows for the copying of rotated logs from one or more systems over the network. If a log already exists at the destination, it will not be copied again.

    .NOTES
    Name       : Invoke-ManualLogArchive
    Author     : Darren Hollinrake
    Version    : 0.3
    DateCreated: 2021-12-28
    DateUpdated: 2021-12-31

    .PARAMETER ComputerName
    The name of the computer from which logs should be pulled.

    .PARAMETER BackupSource
    The location on the computer where the logs are stored. The user running the script should have at least 'Read' access to this location. This should not include the computer name. It should include the name of the share and any subfolder(s) needed for the path to the logs.

    .PARAMETER DestinationPath
    The location where the backed up logs will be archived. Within this location a subfolder with the computer name will be created.

    .EXAMPLE
    Get-Content ".\Hosts.txt" | Invoke-ManualLogArchive -BackupSource "C$\Audit\Archive" -DestinationPath "\\share.lab.lan\Logs"

    Pulls logs from the computers listed in the hosts.txt file. The logs are located on each computer at 'C:\Audit\Archive' which are accessible from the administrative share (C$). The logs will be copied to '\\share.lab.lan\Logs' with a subfolder created for each computer name provided.
    
    #>

    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName,
            ValueFromPipeline,
            Mandatory)]
        [string[]]$ComputerName,
        [Parameter(ValueFromPipelineByPropertyName,
            Mandatory)]
        [string]$BackupSource,
        [Parameter(ValueFromPipelineByPropertyName,
            Mandatory)]
        [string]$DestinationPath
    )
    
    begin {}
    
    process {
        foreach ($Computer in $ComputerName) {
            Write-Verbose "Copying from: $Computer"
            $SourcePath = Join-Path -Path "\\$Computer" -ChildPath "$BackupSource"
            Write-Verbose "Source Path: $SourcePath"
            $DestinationPath = Join-Path -Path $DestinationPath -ChildPath $Computer
            Write-Verbose "Destination Path: $DestinationPath"

            if (!(Test-Path "$DestinationPath")) {
                New-Item -ItemType Directory -Path $DestinationPath -Force | Out-Null
            }
            else {
                $ExcludeLogs = Get-ChildItem -Path "$DestinationPath"
            }

            # Get a list of logs to copy
            $BackupLogs = Get-ChildItem $SourcePath -Exclude $ExcludeLogs

            if (!($BackupLogs.count -ge 1)) {
                Write-Warning "No new logs were found."
                Write-Warning "Ensure the audit script has run or that the logs have not already been copied."
            }
            else {
                $BackupLogs | Copy-Item -Destination $DestinationPath -Recurse -Container -Verbose:$VerbosePreference
            }
        }
    }
    
    end {}
}