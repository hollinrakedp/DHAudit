$ModuleName = $PSScriptRoot | Split-Path -Leaf
$FunctionsToExport = @( (Get-ChildItem -Path $PSScriptRoot\$ModuleName\Public\*.ps1).BaseName )

$manifest = @{
    Path              = ".\$ModuleName\$ModuleName.psd1"
    RootModule        = "$ModuleName.psm1"
    Author            = 'Darren Hollinrake'
    Company           = 'Darren Hollinrake'
    Description       = 'Collection of functions for configuration and management of auditing a Windows system.'
    ModuleVersion     = '0.3'
    FunctionsToExport = $FunctionsToExport
}

if (Test-Path $manifest.Path){
    Update-ModuleManifest @manifest
}
else {
    New-ModuleManifest @manifest
}