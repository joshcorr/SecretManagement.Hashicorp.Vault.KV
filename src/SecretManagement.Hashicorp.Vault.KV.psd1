@{
    ModuleVersion        = '0.0.3'
    CompatiblePSEditions = @('Desktop', 'Core')
    GUID                 = '5dbf943d-d9c0-4db5-88a2-1995043a6305'
    Author               = 'Josh Corrick'
    Copyright            = '(c) 2021 Josh Corrick. All rights reserved.'
    Description          = 'A PowerShell SecretManagement extension for Hashicorp Vault Key Value Engine'
    RootModule           = 'SecretManagement.Hashicorp.Vault.KV.psm1'
    RequiredModules      = @('Microsoft.PowerShell.SecretManagement')
    NestedModules        = './SecretManagement.Hashicorp.Vault.KV.Extension'
    PowershellVersion    = '5.1'
    FunctionsToExport    = @()
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{

        PSData = @{
            # Prerelease string of this module
            Prerelease                 = 'Preview'
            Tags                       = 'SecretManagement', 'HashiCorp', 'Secret', 'Vault', 'MacOS', 'Linux', 'Windows'
            ExternalModuleDependencies = @('Microsoft.PowerShell.SecretManagement')
            LicenseUri                 = 'https://raw.githubusercontent.com/joshcorr/SecretManagement.Hashicorp.Vault.KV/main/LICENSE'
            ProjectUri                 = 'https://github.com/joshcorr/SecretManagement.Hashicorp.Vault.KV'
            # IconUri = ''
            ReleaseNotes               = @'
v0.0.3
Github Actions changes

v0.0.2
Fixes for SecretsManagement RC1

v0.0.1
Initial Preview Release
'@
        }
    }
}
