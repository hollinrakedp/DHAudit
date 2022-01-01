function Set-RegistryAuditRule {
    <#
    .SYNOPSIS
    Set the audit portion of the security access control list (SACL) on a list of registry entries.

    .DESCRIPTION
    This function will set auditing on a single registry key or list of registry keys. These are often referred to as Security Relevant Objects (SROs). Any existing auditing rules will be left alone unless the -Overwrite parameter is specified. Set the parameters to match your requirements.
    The default for the 'SROs' parameter is to import the content of a file 'SRO_Registry.txt' located in the current directory.

    .NOTES
    Name: Set-RegistryAuditRule
    Author: Darren Hollinrake
    Version: 1.3
    DateCreated: 2021-06-29
    DateUpdated: 2021-10-20

    Reference
    ------------
    https://docs.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.registryauditrule

    .PARAMETER SROs
    This parameter identifies the registry entry or list of registry entries against which audit rules should be applied. If this parameter is not specified, the default is to import the contents of 'SRO_Registry.txt' located in the current working directory. The file is strucutured with one registry path per line.

    Example: HKLM:\SYSTEM\CurrentControlSet\Control

    .PARAMETER AuditUser
    This parameter identifies the user or group to which the auditing policy should apply. The default is set to 'Everyone'.

    .PARAMETER AuditProperties
    This parameter sets which type of property events will be audited. A list of valid values can be found below. They are listed in the same order as seen in the GUI.

    Audit Properties
    ----------------------
    Basic Permissions
        FullControl
        ReadKey    (Same as QueryValues, EnumerateSubKeys, Notify, ReadPermissions)
    Advanced Permissions
        FullControl
        QueryValues
        SetValue
        CreateSubKey
        EnumerateSubKeys
        Notify
        CreateLink
        Delete
        ChangePermissions
        TakeOwnership
        ReadPermissions
        *WriteKey    (Same as 'SetValue, CreateSubKey, ReadPermissions')

        *Not a GUI option

    .PARAMETER AuditInheritFlags
    This parameter sets the inherit flags on folders. This determines if files and subfolders inherit the auditing policies. The default setting enables inheritance for both files and subfolders.

    .PARAMETER AuditType
    This parameter sets the type of events (Success/Failure) to audit. The default is to audit success and failure event types.

    .EXAMPLE
    Set-RegistryAuditRule
    
    Applies the default audit rules to the items contained in the SRO_Registry.txt file.

    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [string[]]$SROs = (Get-Content .\SRO_Registry.txt),
        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('User')]
        [string]$AuditUser = "Everyone",
        [Parameter()]
        [string]$AuditProperties = "SetValue, CreateSubKey, Delete, TakeOwnership, WriteKey",
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
            Write-Verbose "No registry item was provided."
            return
        }

        $AuditRule = New-Object System.Security.AccessControl.RegistryAuditRule($AuditUser, $AuditProperties, $AuditInheritFlags, "None", $AuditType)

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

                    Write-Verbose "Setting auditing on: $SRO"
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