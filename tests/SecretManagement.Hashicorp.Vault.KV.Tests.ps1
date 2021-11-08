BeforeDiscovery {
    $s = [io.path]::DirectorySeparatorChar
    $ModuleName = ($PSCommandPath).Replace('.Tests.ps1', '').Split($s)[-1]
}

describe "SecretManagement Usage with $ModuleName" {
    beforeall {
        mock -CommandName Read-Host -MockWith {"yes"}
    }
    It "Should register the vault 'pester'" {
        $VaultParameters = @{ VaultServer = 'http://127.0.0.1:8200'; VaultToken = $(ConvertTo-SecureString -AsPlainText -Force -String 'root'| ConvertFrom-SecureString); VaultAuthType = 'Token'; KVVersion = 'v2'}
        {Register-SecretVault -ModuleName SecretManagement.Hashicorp.Vault.KV -Name pester -VaultParameters $VaultParameters} | Should -Not -Throw
    }
    It "Should unregister the vault 'pester'" {
        {Unregister-SecretVault -Name pester -ErrorAction Stop} | Should -not -Throw
    }
}