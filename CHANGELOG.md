# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

## [2.0.0] - 2021-11-11

*Powershell 5.1 is no longer a supported version for this extension.  
version 1.1.1-Preview is the last 5.1 compatible version*

Major re-write of the token management to make it compatible with [Constrained Language Mode](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_language_modes?view=powershell-7.1#constrained-language-constrained-language)  
Fixes issues with  `Unlock-SecretVault` [#24](https://github.com/joshcorr/SecretManagement.Hashicorp.Vault.KV/issues/24)  
Fixes issue using extension from Terminal [#22](https://github.com/joshcorr/SecretManagement.Hashicorp.Vault.KV/issues/22)  
Updated documentation  

## [1.2.0] - 2021-11-07

Adds `Unlock-SecretVault` [#21](https://github.com/joshcorr/SecretManagement.Hashicorp.Vault.KV/issues/21)  
Adds support for checking tokens lifespan and renewing when they are close to expiring or have already expired. [#11](https://github.com/joshcorr/SecretManagement.Hashicorp.Vault.KV/issues/11)  
Increase verbose messages and fix formatting  
Add Byte as supported data type  
Fix pester tests  s

## [1.1.1] - 2021-08-25

Fixes 'Secrets with nested jsons can be truncated' [#17](https://github.com/joshcorr/SecretManagement.Hashicorp.Vault.KV/issues/17) contribution by [@velkovb](https://github.com/velkovb)

## [1.1.0] - 2021-08-04

Tested with SecretManagement 1.1.0 [#14](https://github.com/joshcorr/SecretManagement.Hashicorp.Vault.KV/issues/14)
Adding tests

## [1.0.2] - 2021-06-10

Default to Hashtable output.

## [1.0.1] - 2021-06-04

Improve Logging. Make Health Checks optional.
Suggested by [Mounting to an existing path in Vault #7](https://github.com/joshcorr/SecretManagement.Hashicorp.Vault.KV/issues/7)

## [1.0.0] - 2021-06-04

Update About; remove Preview Tag

## [0.0.11] - 2021-03-16

More Bug fixes

## [0.0.10] - 2021-03-16

Fix login logic bug

## [0.0.9] - 2021-03-15

Better Token Management; Retrieving Metadata

## [0.0.8] - 2021-03-13

Support Hashtable; Creating Metadata; Removing Vaults

## [0.0.7] - 2021-03-09

Create New Vault; Fix Test-SecretVault

## [0.0.6] - 2021-03-08

Required Secrets Version; Fix folder structure

## [0.0.5] - 2021-03-08

Version Bump

## [0.0.4] - 2021-03-08

More Github Actions changes

## [0.0.3] - 2021-03-08

Github Actions changes

## [0.0.2] - 2021-03-08

Fixes for SecretsManagement RC1

## [0.0.1] - 2020-10-27

Initial Preview Release
