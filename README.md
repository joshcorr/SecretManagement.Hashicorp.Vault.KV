# SecretManagement.Hashicorp.Vault.KV

> [!IMPORTANT]
> This repository is **archived** and no longer maintained.
>
> The upstream dependency [`Microsoft.PowerShell.SecretManagement`](https://github.com/PowerShell/SecretManagement) has been declared feature complete and is no longer actively developed.
> As a result, this extension vault is also being retired.
>
> The last published version on the [PowerShell Gallery](https://www.powershellgallery.com/packages/SecretManagement.Hashicorp.Vault.KV) remains available for use, but no further updates, bug fixes, or security patches will be provided.
>
> For secrets management, consider alternatives such as the [Hashicorp Vault provider for OpenTofu/Terraform](https://registry.terraform.io/providers/hashicorp/vault/latest/docs), the [Vault Agent](https://developer.hashicorp.com/vault/docs/agent-and-proxy/agent), or other passwordless authentication methods.

[![PSGallery][]][PSGalleryLink]

A PowerShell SecretManagement extension for Hashicorp Vault key- value (KV) Engine. This supports version 1, version2, and  cubbyhole (similar to v1). It does not currently support all of the version 2 features like versioned secrets.

| Extension Version | 6.0+ | 5.1 | Constrained Language Mode |
| ----------------- | ---- | --- | ------------------------- |
| 1.x.x             | Yes  | Yes | No                        |
| 2.x.x             | Yes  | No  | Yes                       |

> **NOTE: This project is not maintained by Hashicorp.**  
> **I work on this in my free time because I use Vault.**  
> If Hashicorp would like to adopt this module please reach out.  

## QuickStart

When registering a vault you need to provide at least these options:

```PowerShell
Register-SecretVault -ModuleName SecretManagement.Hashicorp.Vault.KV -Name PowerShellTest -VaultParameters @{ VaultServer = 'http://vault.domain.local:8200'; VaultAuthType = 'Token'}
```

To disable HTTPS certificate checks (e.g. self-signed certs) use the `VaultSkipVerify` parameter

```PowerShell
Register-SecretVault -ModuleName SecretManagement.Hashicorp.Vault.KV -Name PowerShellTest -VaultParameters @{ VaultServer = 'https://vault.domain.local:8200'; VaultAuthType = 'Token'; VaultSkipVerify = $true}
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

[PSGallery]: https://img.shields.io/powershellgallery/v/SecretManagement.Hashicorp.Vault.KV?include_prereleases
[PSGalleryLink]: https://www.powershellgallery.com/packages/SecretManagement.Hashicorp.Vault.KV
