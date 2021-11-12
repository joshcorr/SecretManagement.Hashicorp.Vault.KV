@{
    ModuleVersion     = '2.0.0'
    RootModule        = 'SecretManagement.Hashicorp.Vault.KV.Extension.psm1'
    FunctionsToExport = @('Set-Secret', 'Get-Secret', 'Remove-Secret', 'Get-SecretInfo', 'Test-SecretVault', 'Unlock-SecretVault', 'Unregister-SecretVault')
}