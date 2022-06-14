function Get-NTFSFolderPermission {
    <#
    .SYNOPSIS
    Get NTFS Folder permissions

    .DESCRIPTION
    This function returns the NTFS Permission applied against the folder specified. If a depth is specified, the subfolders up to that depth will also be returned.

    .NOTES
    Name         - Get-NTFSFolderPermission
    Version      - 0.1
    Author       - Darren Hollinrake
    Date Created - 2022-06-11
    Date Updated - 
    
    .PARAMETER Path
    The path to the folder whose permissions should be retrieved. If the 'Depth' parameter is also supplied, this is the root folder from which the depth is determined.

    .PARAMETER Depth
    The depth to which folder permissions should be retrieved. If this parameter is not specified, only the folder specfied in the 'Path' parameter will be returned.

    .EXAMPLE
    Get-NTFSFolderPermission -Path "$env:USERPROFILE"
    Folder     : C:\Users\User01
    Type       : Allow
    Identity   : NT AUTHORITY\SYSTEM
    Permission : FullControl
    Inherited  : False

    Folder     : C:\Users\User01
    Type       : Allow
    Identity   : BUILTIN\Administrators
    Permission : FullControl
    Inherited  : False

    Folder     : C:\Users\User01
    Type       : Allow
    Identity   : Computer01\User01
    Permission : FullControl
    Inherited  : False

    This example will output to the console the permissions on the user profile folder for the current user.

    .EXAMPLE
    Get-NTFSFolderPermission -Path "$env:USERPROFILE" -Depth 2 | Export-Csv -Path "$env:USERPROFILE\Desktop\report.csv" -NoTypeInformation
    This example will export the collected information to a CSV file on the current users desktop

    #>
    [CmdletBinding(DefaultParameterSetName = 'Single')]
    param (
        [Parameter(ValueFromPipelineByPropertyName, ParameterSetName = 'Single')]
        [Parameter(ValueFromPipelineByPropertyName, ParameterSetName = 'Recurse')]
        [string]$Path,
        [Parameter(ValueFromPipelineByPropertyName, ParameterSetName = 'Recurse')]
        [int]$Depth = 0
    )

    $Acl = Get-Acl -Path $Path
    foreach ($Access in $Acl.Access) {
        $Properties = [PSCustomObject]@{
            Folder     = (Resolve-Path "$Path").Path | Convert-Path
            Type       = $Access.AccessControlType
            Identity   = $Access.IdentityReference
            Permission = $Access.FileSystemRights
            Inherited  = $Access.IsInherited
        }
        $Properties
    }
    switch ($PsCmdlet.ParameterSetName) {
        Recurse {
            $Folders = Get-ChildItem -Path "$Path" -Directory -Recurse -Depth $Depth
            foreach ($Folder in $Folders) {
                $Acl = Get-Acl -Path $Folder.FullName
                foreach ($Access in $Acl.Access) {
                    $Properties = [PSCustomObject]@{
                        Folder     = $Folder.FullName
                        Type       = $Access.AccessControlType
                        Identity   = $Access.IdentityReference
                        Permission = $Access.FileSystemRights
                        Inherited  = $Access.IsInherited
                    }
                    $Properties
                }
            }
        }
    }
}