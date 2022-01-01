function Set-FileSystemAuditRule {
    <#
    .SYNOPSIS
    Set the audit portion of the security access control list (SACL) on a file/folder or list of files/folders specified.

    .DESCRIPTION
    This function will set auditing on a single file/folder or list of files/folders. These are often referred to as Security Relevant Objects (SROs). Any existing auditing rules will be left alone unless the -Overwrite parameter is specified. Set the parameters to match your requirements.
    The default for the 'SROs' parameter is to import the content of a file 'SRO_FileSystem.txt' located in the current directory.

    .NOTES
    Name: Set-FileSystemAuditRule
    Author: Darren Hollinrake
    Version: 1.3
    DateCreated: 2021-06-29
    DateUpdated: 2021-10-20

    Reference
    ------------
    https://docs.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.filesystemauditrule

    .PARAMETER SROs
    This parameter identifies the file/folder or list of files/folders against which audit rules should be applied. This parameter accepts pipeline input. The path to files/folders can be absolute or relative to the currenty working directory.
    If this parameter is not specified, the default is to import the contents of 'SRO_FileSystem.txt' located in the current working directory. The file is strucutured with one folder/file path per line.

    Example: C:\Windows\System32

    .PARAMETER AuditUser
    This parameter identifies the user or group to which the auditing policy should apply.
    The default is set to 'Everyone'.

    .PARAMETER AuditProperties
    This parameter sets which type of property events will be audited. There are 3 sets of audit properties: Full Control, Basic Permission, Advanced Permission
    The 'Full Control' audits all properties, 'Basic Permission' and 'Advanced Permission' matches the checkboxes seen in the GUI for the basic and advanced permissions respectively. Below is a full list of Audit Properties that can be set.
    Audit Properties
        Basic Permission
            Modify
            ReadAndExecute
            Read
            Write
        Advanced Permission
            FullControl
            ExecuteFile
            ReadData
            ReadAttributes
            ReadExtendedAttributes
            WriteData
            AppendData
            WriteAttributes
            WriteExtendedAttributes
            DeleteSubdirectoriesAndFiles
            Delete
            ReadPermissions
            ChangePermissions
            TakeOwnership

    .PARAMETER AuditInheritFlags
    This parameter sets the Inheritance flags which specify the semantics of inheritance for access control entries (ACEs). This determines if files and subfolders inherit the auditing policies. This parameter allows for the bitwise combination of values. The default setting enables inheritance for both files and subfolders.

    Valid Values
    =================
    None    (0)
    The ACE is not inherited by child objects.

    ContainerInherit    (1)
    The ACE is inherited by child container objects.

    ObjectInherit   (2)
    The ACE is inherited by child leaf objects.

    .PARAMETER AuditType
    This parameter Specifies the conditions for auditing attempts to access a securable object. This parameter allows for the bitwise combination of values. The default is to audit success and failure event types.

    Valid Values
    =================
    None    (0)
    No access attempts are to be audited.

    Success (1)
    Successful access attempts are to be audited.

    Failure (2)
    Failed access attempts are to be audited.

    .EXAMPLE
    Set-FileSystemAuditRule
    
    Applies the default audit rules to the items contained in the SRO_FileSystem.txt file.

    .EXAMPLE
    'C:\File\SRO.txt', 'C:\Directory\AuditMe' | Set-FileSystemAuditRule

    Applies the default audit rules to to the 'SRO.txt' file and 'AuditMe' directory.

    .EXAMPLE
    Set-FileSystemAuditRule -SROs 'C:\File\SRO.txt' -AuditUser Administrator
    Applies the default audit rule to the 'SRO.txt' file only for the local 'Administrator' user.

    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [string[]]$SROs = (Get-Content .\SRO_FileSystem.txt),
        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('User')]
        [string]$AuditUser = "Everyone",
        [Parameter()]
        [string]$AuditProperties = "ExecuteFile, ReadData, WriteData, AppendData, DeleteSubdirectoriesAndFiles, Delete, ChangePermissions, TakeOwnership",
        [Parameter()]
        [ValidateSet("None", "ContainerInherit", "ObjectInherit", "ContainerInherit, ObjectInherit")]
        [string]$AuditInheritFlags = "ContainerInherit, ObjectInherit",
        [Parameter()]
        [ValidateSet("Success", "Failure", "Success, Failure")]
        [string]$AuditType = "Success, Failure",
        [Parameter()]
        [switch]$Overwrite
    )
    
    begin {
        if ([string]::IsNullOrEmpty($SROs)) {
            Write-Verbose "No file or directory was provided."
            return
        }

        $AuditRuleFolder = New-Object System.Security.AccessControl.FileSystemAuditRule($AuditUser, $AuditProperties, $AuditInheritFlags, "None", $AuditType)
        $AuditRuleFile = New-Object System.Security.AccessControl.FileSystemAuditRule($AuditUser, $AuditProperties, "None", "None", $AuditType)

        Write-Verbose "Setting auditing rules for SROs"
    }
    
    process {
        foreach ($SRO in $SROs) {
            if ($PSCmdlet.ShouldProcess("$SRO")) {
                if (!(Test-Path $SRO)) {
                    Write-Verbose "The SRO does not exist: $SRO"
                }
                else {
                    $ACL = Get-ACL $SRO -Audit
                    if ((Get-Item "$SRO").PSIsContainer) {
                        Write-Verbose "SRO Type: Folder"
                        $AuditRule = $AuditRuleFolder
                    }
                    else {
                        Write-Verbose "SRO Type: File"
                        $AuditRule = $AuditRuleFile
                    }
                    switch ($Overwrite) {
                        $True {
                            Write-Verbose "Removing any existing audit rules"
                            $ACL.GetAuditRules($True, $False, [System.Security.Principal.SecurityIdentifier]) | Foreach-Object { $ACL.RemoveAuditRule($_) | Out-Null }
                            Write-Verbose "Adding Audit Rule"
                            $ACL.AddAuditRule($AuditRule)
                        }
                        $false {
                            Write-Verbose "Adding Audit Rule"
                            $ACL.AddAuditRule($AuditRule)
                        }
                    }
                    $ACL | Set-Acl $SRO
                }
                
            }
        }
    }
    
    end {
        Write-Verbose "Finished setting auditing rules for SROs"
    }
}