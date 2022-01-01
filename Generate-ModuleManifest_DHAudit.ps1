$manifest = @{
    Path              = '.\DHAudit\DHAudit.psd1'
    RootModule        = 'DHAudit.psm1'
    Author            = 'Darren Hollinrake'
    Company           = 'Darren Hollinrake'
    Description       = 'Collection of functions for configuration and management of auditing a Windows system.'
    ModuleVersion     = '0.2'
    FunctionsToExport = @('Invoke-LogArchive','Invoke-LogRotate','Invoke-ManualLogArchive','Set-ActiveDirectoryAuditRule','Set-FileSystemAuditRule','Set-RegistryAuditRule')
}
New-ModuleManifest @manifest