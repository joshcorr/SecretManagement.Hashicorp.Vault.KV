@{
    ModuleVersion        = '0.0.11'
    CompatiblePSEditions = @('Desktop', 'Core')
    GUID                 = '5dbf943d-d9c0-4db5-88a2-1995043a6305'
    Author               = 'Josh Corrick'
    Copyright            = '(c) 2021 Josh Corrick. All rights reserved.'
    Description          = 'A PowerShell SecretManagement extension for Hashicorp Vault Key Value Engine'
    RequiredModules      = @(@{ModuleName = "Microsoft.PowerShell.SecretManagement"; ModuleVersion = "0.9.1"; GUID = "a5c858f6-4a8e-41f1-b1ee-0ff8f6ad69d3" })
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
v0.0.10 - v0.0.11
Fix login logic bug

v0.0.9
Better Token Management; Retrieving Metadata

v0.0.8
Support Hashtable; Creating Metadata; Removing Vaults

v0.0.7
Create New Vault; Fix Test-SecretVault

v0.0.6
Required Secrets Version; Fix folder structure

v0.0.5
Version Bump

v0.0.4
More Github Actions changes

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
