#Requires -Module ActiveDirectory
function Set-ActiveDirectoryAuditRule {
    <#
    .SYNOPSIS
    Set the audit portion of the security access control list (SACL) on a list of Active Directory objects.

    .DESCRIPTION

    .NOTES
    Name: Set-ActiveDirectoryAuditRule
    Author: Darren Hollinrake
    Version: 0.1
    DateCreated: 2021-10-25
    DateUpdated: 2021-10-26

    Reference
    ------------
    https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryauditrule

    .PARAMETER SROs
    This parameter identifies the Active Directory path or list of Active Directory paths against which audit rules should be applied. This is accomplished using the Distinguished Name (DN) of an object. Each path should be prepended with 'AD:\' to allow for the use of the built-in PSDrive for Active Directory. If a path is provided without the drive, it will automatically be added.

    Example: AD:\cn=example,dc=domain,dc=com
             cn=example2,dc=domain,dc=com

    .PARAMETER IdentityReference
    Represents the identity that should be audited. This should be in the format of "domain\username" or "domain\groupname". For certain accounts, the domain can be omitted. (I.E. 'Everyone'). If no value is provided, the default value is 'Everyone'.

    .PARAMETER ActiveDirectoryRights
    Specifies the access rights that are assigned to an Active Directory Domain Services object. This parameter allows for the bitwise combination of values. If no value is provided, the default value is 'GenericAll'.

    Valid Values
    =================
    CreateChild (1)
    The right to create children of the object.

    DeleteChild	(2)
    The right to delete children of the object.

    ListChildren    (4)
    The right to list children of this object. For more information about this right, see the Controlling Object Visibility article.

    Self    (8)
    The right to perform an operation that is controlled by a validated write access right.

    ReadProperty    (16)
    The right to read properties of the object.
    
    WriteProperty   (32)
    The right to write properties of the object.

    DeleteTree  (64)
    The right to delete all children of this object, regardless of the permissions of the children.

    ListObject  (128)
    The right to list a particular object. For more information about this right, see the see the Controlling Object Visibility article.

    ExtendedRight   (256)
    A customized control access right. For a list of possible extended rights, see the Extended Rights article. For more information about extended rights, see the Control Access Rights article.

    Delete  (65536)
    The right to delete the object.

    ReadControl (131072)
    The right to read data from the security descriptor of the object, not including the data in the SACL.

    GenericExecute  (131076)
    The right to read permissions on, and list the contents of, a container object.

    GenericWrite    (131112)
    The right to read permissions on this object, write all the properties on this object, and perform all validated writes to this object.
    
    GenericRead (131220)
    The right to read permissions on this object, read all the properties on this object, list this object name when the parent container is listed, and list the contents of this object if it is a container.

    WriteDacl   (262144)
    The right to modify the DACL in the object security descriptor.

    WriteOwner  (524288)
    The right to assume ownership of the object. The user must be an object trustee. The user cannot transfer the ownership to other users.

    GenericAll  (983551)
    The right to create or delete children, delete a subtree, read and write properties, examine children and the object itself, add and remove the object from the directory, and read or write with an extended right.

    Synchronize (1048576)
    The right to use the object for synchronization. This right enables a thread to wait until that object is in the signaled state.

    AccessSystemSecurity    (16777216)
    The right to get or set the SACL in the object security descriptor.

    .PARAMETER AuditFlags
    Specifies the conditions for auditing attempts to access a securable object. This parameter allows for the bitwise combination of values. If no value is specified, the default value is 'Failure'.

    Valid Values
    =================
    None (0)
    No access attempts are to be audited.

    Success (1)
    Successful access attempts are to be audited.

    Failure (2)
    Failed access attempts are to be audited.

    .PARAMETER ActiveDirectorySecurityInheritance
    The ActiveDirectorySecurityInheritance specifies if, and how, ACE information is applied to an object and its descendents. If no value is specified, the default value is 'All'.

    Valid Values
    =================
    None    (0)
    Indicates no inheritance. The ACE information is only used on the object on which the ACE is set. ACE information is not inherited by any descendents of the object.

    All (1)
    Indicates inheritance that includes the object to which the ACE is applied, the object's immediate children, and the descendents of the object's children.

    Descendents (2)
    Indicates inheritance that includes the object's immediate children and the descendants of the object's children, but not the object itself.

    SelfAndChildren (3)
    Indicates inheritance that includes the object itself and its immediate children. It does not include the descendents of its children.
    
    Children    (4)
    Indicates inheritance that includes the object's immediate children only, not the object itself or the descendents of its children.

    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [string[]]$SROs,
        [Parameter()]
        [Alias('AuditUser', 'Identity')]
        [Security.Principal.NTAccount]$IdentityReference = 'Everyone',
        [Parameter()]
        [Alias('AuditProperties', 'ADRights')]
        [System.DirectoryServices.ActiveDirectoryRights]$ActiveDirectoryRights = 'GenericAll',
        [Parameter()]
        [ValidateSet("Success", "Failure", "Success, Failure")]
        [Alias('AuditType')]
        [System.Security.AccessControl.AuditFlags]$AuditFlags = 'Failure',
        [Parameter()]
        [Alias('InheritanceType')]
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]$ActiveDirectorySecurityInheritance = 'All'
    )
    
    begin {
        Import-Module ActiveDirectory
        $AuditRule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($IdentityReference, $ActiveDirectoryRights, $AuditFlags)
        if (!(Get-PSDrive -Name 'AD' -ErrorAction SilentlyContinue)) {
            Write-Error "The 'AD' drive is not available."
            return
        }
        if ([string]::IsNullOrEmpty($SROs)) {
            Write-Verbose "No SRO Path was provided."
            return
        }
    }
    
    process {
        foreach ($SRO in $SROs) {
            if ($PSCmdlet.ShouldProcess("$SRO")) {
                if (!($SRO.StartsWith('AD:\'))) {
                    $SRO = Join-Path -Path 'AD:\' -ChildPath $SRO
                }
                if (!(Test-Path $SRO)) {
                    Write-Verbose "The SRO does not exist: $SRO"
                }
                else {
                    Write-Verbose "Setting auditing on: $SRO"
                    $ACL = Get-ACL $SRO -Audit
                    Write-Verbose "Adding Audit Rule"
                    $ACL.AddAuditRule($AuditRule)
                    $ACL | Set-Acl $SRO
                }
            }
        }
    }
    
    end {
        Write-Verbose "Finished setting auditing rules for SROs"
    }
}