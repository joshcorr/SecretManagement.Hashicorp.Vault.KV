# SecretManagement.Hashicorp.Vault.KV

[![GitHubSuper-Linter][]][GitHubSuper-LinterLink]
[![PSGallery][]][PSGalleryLink]
[![SupportBadge][]][SupportBadge]

A PowerShell SecretManagement extension for Hashicorp Vault Key Value (KV) Engine. This supports version 1, version2, and  cubbyhole (similar to v1). It does not currently support all of the version 2 features like versioned secrets. This extension only supports PowerShell 6+

> **NOTE: This project is not maintained by Hashicorp.**  
> **I work on this in my free time because I use Vault.**  
> If Hashicorp would like to adopt this module please reach out.  

## QuickStart

When registering a vault you need to provide at least these options:

```PowerShell
Register-SecretVault -ModuleName SecretManagement.Hashicorp.Vault.KV -Name PowerShellTest -VaultParameters @{ VaultServer = 'http://vault.domain.local:8200'; VaultAuthType = 'Token'}
```

The vault name should match exactly, as Hashicorp vault is case sensitive. If no VaultParameters are provided the functions will prompt you on the first execution in your session. Additionally you may provide which version of KV you are using when registering. It defaults to version 2 of KV.  

```PowerShell
$VaultParameters = @{ VaultServer = 'https://vault-cluster.domain.local'
   VaultToken=$(Read-Host -AsSecureString | ConvertFrom-SecureString)
   KVVersion = 'v1'}
```

If you stored your secrets in a flat structure (i.e. no slashes in your path),
You may want to return all secrets as a PSCredential. You can do this by providing the following:

```powershell
$VaultParameters @{ ...
    OutputType = 'PSCredential'
}
```

The Default is to return it as a Hashtable.

You may provide either a single text string or a hashtable to the `-Secret` parameter.

## KV Version 2 distinctions

- Get-Secret only retrieves the newest secret
- Get-SecretInfo retrieves the Hashicorp Metadata
- Set-Secret Adds/Updates without CheckAndSet. Althought it can be passed with `-Metadata @{cas=<versionNumber>}`
- Remove-Secret Removes the latest version of a secret

[GitHubSuper-Linter]: https://github.com/joshcorr/SecretManagement.Hashicorp.Vault.KV/workflows/ci/badge.svg
[GitHubSuper-LinterLink]: https://github.com/marketplace/actions/super-linter

[PSGallery]: https://img.shields.io/powershellgallery/v/SecretManagement.Hashicorp.Vault.KV?include_prereleases
[PSGalleryLink]: https://www.powershellgallery.com/packages/SecretManagement.Hashicorp.Vault.KV
[SupportBadge]: https://img.shields.io/powershellgallery/p/SecretManagement.Hashicorp.Vault.KV?label=6.0%2B&logo=powershell