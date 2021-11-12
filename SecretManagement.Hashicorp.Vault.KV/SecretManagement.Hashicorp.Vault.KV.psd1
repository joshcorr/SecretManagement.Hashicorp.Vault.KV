@{
    ModuleVersion        = '2.0.0'
    CompatiblePSEditions = @('Core')
    GUID                 = '5dbf943d-d9c0-4db5-88a2-1995043a6305'
    Author               = 'Josh Corrick'
    Copyright            = '(c) 2021 Josh Corrick. All rights reserved.'
    Description          = 'A PowerShell SecretManagement extension for Hashicorp Vault Key Value Engine'
    NestedModules        = './SecretManagement.Hashicorp.Vault.KV.Extension'
    PowershellVersion    = '6.0'
    FunctionsToExport    = @()
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{

        PSData = @{
            # Prerelease string of this module
            # Prerelease                 = 'Preview'
            Tags                       = 'SecretManagement', 'HashiCorp', 'Secret', 'Vault', 'MacOS', 'Linux', 'Windows'
            ExternalModuleDependencies = @('Microsoft.PowerShell.SecretManagement')
            LicenseUri                 = 'https://raw.githubusercontent.com/joshcorr/SecretManagement.Hashicorp.Vault.KV/main/LICENSE'
            ProjectUri                 = 'https://github.com/joshcorr/SecretManagement.Hashicorp.Vault.KV'
            # IconUri = ''
            ReleaseNotes               = 'https://raw.githubusercontent.com/joshcorr/SecretManagement.Hashicorp.Vault.KV/main/CHANGELOG.md'
        }
    }
}
