@{
# RootModule = ''
ModuleVersion = '0.0.1'
CompatiblePSEditions = @('Desktop', 'Core')
GUID = '5dbf943d-d9c0-4db5-88a2-1995043a6305'
Author = 'Joshua Corrick'
Copyright = '(c) 2020 Joshua Corrick. All rights reserved.'
Description = 'A PowerShell SecretManagement extension for Hashicorp Vault Key Value Engine'
RequiredModules = @('Microsoft.PowerShell.SecretManagement')
NestedModules = './SecretManagement.Hashicorp.Vault.KV.Extension/SecretManagement.Hashicorp.Vault.KV.Extension.psd1'
PowershellVersion = '5.1'
FunctionsToExport = @()
CmdletsToExport = @()
VariablesToExport = @()
AliasesToExport = @()
PrivateData = @{

    PSData = @{
        Tags = 'SecretManagement', 'HashiCorp', 'Secret', 'Vault', 'MacOS', 'Linux', 'Windows'
        LicenseUri = 'https://raw.githubusercontent.com/joshcorr/SecretManagement.Hashicorp.Vault.KV/main/LICENSE'
        ProjectUri = 'https://github.com/joshcorr/SecretManagement.Hashicorp.Vault.KV'
        # IconUri = ''
        ReleaseNotes = @'
v0.0.1
Initial Release
'@

        # Prerelease string of this module
        # Prerelease = ''

        # External dependent modules of this module
        # ExternalModuleDependencies = @()

    }

}

}
