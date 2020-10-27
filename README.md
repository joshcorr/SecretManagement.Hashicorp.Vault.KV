# SecretManagement.Hashicorp.Vault.KV
A PowerShell SecretManagement extension for Hashicorp Vault Key Value (KV) Engine. This supports version 1, version2, and  cubbyhole (similar to v1). It does not currently support all of the version 2 features like versioned secrets, or metadata.

## QuickStart
When registering a vault you need to provide at least these options:
```PowerShell
Register-SecretVault -ModuleName SecretManagement.Hashicorp.Vault.KV -Name PowerShellTest -VaultParameters @{ VaultServer = 'http://vault.domain.local:8200'; VaultToken = '<orNot>'}
```
The vault name should match exactly as Hashicorp vault is case sensative. If no VaultParameters are provided the functions will prompt you on the first execution. Additionally you may provide which version of KV you are using when registering. It defaults to version 2 of KV.  

```PowerShell
$VaultParameters = @{ VaultServer = 'https://vault-cluster.domain.local'
   VaultToken = '<s.somecharactershere>'
   KVVersion = 'v2'}
```

## KV Version 2 distinctions
 - Get-Secret only retrievs the newest secret
 - Set-Secret Adds/Updates without CheckAndSet.
 - Remove-Secret Completely Removes the secret and all versions

## TO DO
 - Create a vault if it doesn't exist
 - Allow token updating
 - Allow options for KV2 version retrieval