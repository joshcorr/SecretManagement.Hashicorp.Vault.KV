# For ConvertTo-ReadOnlyDictonary
using namespace System.Collections.ObjectModel
using namespace System.Collections.Generic
# Private Helper Functions
enum HashicorpVaultConfigValues {
    VaultServer
    VaultAuthType
    VaultToken
    VaultAPIVersion
    KVVersion
    OutputType
    Verbose
}
enum HashicorpVaultAuthTypes {
    None
    AppRole
    LDAP
    userpass
    Token
    kerberos
}
class HashicorpVaultKV {
    static [string] $VaultServer
    static [HashicorpVaultAuthTypes] $VaultAuthType = 'None'
    static [Securestring] $VaultToken
    static [string] $VaultAPIVersion = 'v1'
    static [string] $KVVersion = 'v2'
    static [string] $OutputType = 'Hashtable'
    static [bool] $Verbose
}
function Invoke-CustomWebRequest {
    <#
    .SYNOPSIS
        Custom Web Request function to support non standard methods
    #>
    [Cmdletbinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Uri,
        [Parameter(Mandatory)]
        [object]$Headers,
        [Parameter(Mandatory)]
        [string]$Method
    )
    Add-Type -AssemblyName System.Net.Http
    $Client = New-Object -TypeName System.Net.Http.HttpClient
    $Client.DefaultRequestHeaders.Accept.Add($headers['Accept'])
    $Request = New-Object -TypeName System.Net.Http.HttpRequestMessage
    $Request.Method = $method
    $Request.Headers.Add('X-Vault-Token', $headers['X-Vault-Token'])
    $Request.Headers.Add('ContentType', $headers['Content-type'])
    $Request.RequestUri = $Uri

    $Result = $Client.SendAsync($Request)
    $StatusCode = $Result.Result.StatusCode
    if ($StatusCode -eq "OK") {
        $Result.Result.Content.ReadAsStringAsync().Result | ConvertFrom-Json
    } else {
        Throw "$statuscode for $method on $uri"
    }
    $Client.Dispose()
    $Request.Dispose()
}
function ConvertTo-ReadOnlyDictionary {
    <#
        .SYNOPSIS
        Converts a hashtable to a ReadOnlyDictionary[String,Object]. Needed for SecretInformation
        .NOTES
        From Justin Grote at https://github.com/JustinGrote/SecretManagement.KeePass/blob/main/SecretManagement.KeePass.Extension/Private/ConvertTo-ReadOnlyDictionary.ps1
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)][hashtable]$hashtable
    )
    process {
        $dictionary = [SortedDictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
        $hashtable.GetEnumerator().foreach{
            $dictionary[$_.Name] = $_.Value
        }
        [ReadOnlyDictionary[string, object]]::new($dictionary)
    }
}
function Test-VaultVariable {
    <#
    .SYNOPSIS
        Ensures that all Static Variables are configured
    #>
    [Cmdletbinding()]
    param (
        [Parameter()]
        [hashtable]$Arguments
    )
    foreach ($k in $Arguments.GetEnumerator()) {
        if ($k.Key -notin [HashicorpVaultConfigValues].GetEnumNames()) {
            Write-Warning -Message "$($k.Key) not in accepted config values, skipping"
            continue
        }
        if ($k.key -eq 'VaultToken') {
            [HashicorpVaultKV]::$($k.Key) = $($k.Value | ConvertTo-SecureString)
            continue
        }
        if ($null -eq [HashicorpVaultKV]::$($k.key) -or [HashicorpVaultKV]::$($k.key) -ne $($k.key)) {
            [HashicorpVaultKV]::$($k.Key) = $k.Value
        }
    }
}
function Invoke-VaultToken {
    <#
    .SYNOPSIS
        Retrieves Token based on Supported Credential
    #>
    process {
        $additionalInvokeRestArguments = @{};
        switch ([HashicorpVaultKV]::VaultAuthType) {
            "AppRole" {
                $Credential = Get-Credential -Message "Please Enter Role-Id and Secret-Id"
                $UserName = $Credential.UserName
                #Following TryParse from https://stackoverflow.com/a/62416925
                $AppRoleResult = [System.Guid]::empty
                if (-not [System.Guid]::TryParse($UserName, [System.Management.Automation.PSReference]$AppRoleResult)) {
                    throw "Approle Role-id must be a valid guid"
                }
                $UserLogin = "$([HashicorpVaultKV]::VaultServer)/$([HashicorpVaultKV]::VaultAPIVersion)/auth/approle/login"
                $UserPassword = "{`"role_id`":`"$UserName`",`"secret_id`":`"$($Credential.GetNetworkCredential().Password)`"}"
                continue
            }
            "LDAP" {
                $Credential = Get-Credential -Message "Please Enter LDAP credentials"
                $UserName = $Credential.UserName
                $UserLogin = "$([HashicorpVaultKV]::VaultServer)/$([HashicorpVaultKV]::VaultAPIVersion)/auth/ldap/login/$UserName"
                $UserPassword = "{`"password`":`"$($Credential.GetNetworkCredential().Password)`"}"
                continue
            }
            "kerberos" {
                $UserLogin = "$([HashicorpVaultKV]::VaultServer)/$([HashicorpVaultKV]::VaultAPIVersion)/auth/kerberos/login"
                $additionalInvokeRestArguments.Add('UseDefaultCredentials', $true);
                continue
            }
            "Token" {
                [HashicorpVaultKV]::VaultToken = (Get-Credential -UserName Token -Message "Please Enter the token").Password
                break
            }
            "userpass" {
                $Credential = Get-Credential -Message "Please Enter UserName and Password credentials"
                $UserName = $Credential.UserName
                $UserLogin = "$([HashicorpVaultKV]::VaultServer)/$([HashicorpVaultKV]::VaultAPIVersion)/auth/userpass/login/$UserName"
                $UserPassword = "{`"password`":`"$($Credential.GetNetworkCredential().Password)`"}"
                continue
            }
            default {
                throw "This shouldn't be possible please create an issue on  https://github.com/joshcorr/SecretManagement.Hashicorp.Vault.KV"
            }
        }
        try {
            if ([HashicorpVaultKV]::VaultAuthType -ne 'Token') {
                $auth = (Invoke-RestMethod -Method POST -Uri $UserLogin -Body $UserPassword @additionalInvokeRestArguments)
                [HashicorpVaultKV]::VaultToken = $auth.auth.client_token | ConvertTo-SecureString -AsPlainText -Force
            }
            #Register an Event to prompt whent he token is expiring
            #Register-ObjectEvent
        } catch {
            throw
        } finally {
            $auth, $UserName, $UserPassword, $UserLogin, $Credential, $AppRoleResult = $null
        }
    }
}
function New-Vault {
    <#
    .SYNOPSIS
        Creates a new vault
    #>
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName, Mandatory)]
        [string] $VaultName,
        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable] $AdditionalParameters
    )
    process {
        try {
            $serverURI = $([HashicorpVaultKV]::VaultServer), $([HashicorpVaultKV]::VaultAPIVersion), 'sys/mounts', $VaultName -join '/'

            if ([HashicorpVaultKV]::KVVersion -eq 'v1') {
                $version = '1'
            } else {
                $version = '2'
            }
            $VaultSplat = @{
                URI     = $serverURI
                Method  = 'POST'
                Headers = New-VaultAPIHeader
            }
            $VaultOptions = @{
                type        = 'kv'
                description = $AdditionalParameters['Description']
                options     = @{
                    version = $version
                }
            }
            $body = $VaultOptions | ConvertTo-Json

            if ($null -ne $body) { $VaultSplat['Body'] = $body }
            Invoke-RestMethod @VaultSplat
        } catch {
            throw
        } finally {
            #Probably unecessary, but precautionary.
            $VaultSplat, $VaultOption, $listuri, $uri, $Method, $Body = $null
        }
    }
}
function Remove-Vault {
    <#
    .SYNOPSIS
        Removes a vault
    #>
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName, Mandatory)]
        [string] $VaultName,
        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable] $AdditionalParameters
    )
    process {
        try {
            $serverURI = $([HashicorpVaultKV]::VaultServer), $([HashicorpVaultKV]::VaultAPIVersion), 'sys/mounts', $VaultName -join '/'
            Write-Verbose "Removing $VaultName. $AdditionalParameters['Description']"
            $VaultSplat = @{
                URI     = $serverURI
                Method  = 'DELETE'
                Headers = New-VaultAPIHeader
            }

            Invoke-RestMethod @VaultSplat
        } catch {
            throw
        } finally {
            #Probably unecessary, but precautionary.
            $VaultSplat, $serverURI = $null
        }
    }
}
function New-VaultAPIHeader {
    <#
    .SYNOPSIS
        Creates a header for an API call
    .NOTES
        Token conversion From https://stackoverflow.com/a/57431985
    #>
    @{
        'Content-Type'  = 'application/json'
        'Accept'        = 'application/json'
        'X-Vault-Token' = $([System.Net.NetworkCredential]::new("", $([HashicorpVaultKV]::VaultToken)).Password)
    }
}
function New-VaultAPIBody {
    <#
    .SYNOPSIS
        Creates the Body of an API call for Set-Secret
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [hashtable[]]$Data
    )
    try {
        $CombinedData = @{}
        foreach ($ht in $Data.GetEnumerator()) {
            #Because of multiple Hashtables
            foreach ($d in $ht.GetEnumerator()) {
                if ($d.key -in $CombinedData.Keys ) {
                    Write-Verbose -Message "Key: '$($d.key)' already provided"
                }
                if ($d.key -in @('cas', 'checkandset')) {
                    $options = @{"cas" = [int]$d.value }
                }
                $CombinedData["$($d.key)"] = $d.value
            }
        }
        if ([HashicorpVaultKV]::KVVersion -eq 'v1') {
            $Tempbody = $CombinedData
        } elseif ([HashicorpVaultKV]::KVVersion -eq 'v2') {
            $Tempbody = @{
                data = $CombinedData
            }
            if ($null -ne $options) {
                $Tempbody['options'] = $options
            }
        }
        $OutputBody = $Tempbody | ConvertTo-Json -Depth 10
        return $OutputBody
    } catch {
        throw
    } finally {
        $CombinedData, $OutputBody, $Tempbody, $options, $ht, $data = $Null
    }
}
function Resolve-VaultSecretPath {
    <#
    .SYNOPSIS
        Walks the Hashicorp KV strucutre to list secrets
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$VaultName,
        [Parameter()]
        [string]$Path
    )
    $Data = (Invoke-VaultAPIQuery -VaultName $VaultName -SecretName $Path).data
    foreach ($k in $data.Keys) {
        $KeyPath = $Path, $k -join '/'

        if ($KeyPath.endswith('/')) {
            $ResolveSplat = @{
                VaultName = $VaultName
                Path      = $keyPath.Trim('/')
            }
            Resolve-VaultSecretPath @ResolveSplat
        } else {
            $KeyPath.TrimStart('/')
        }
    }
}
function Invoke-VaultAPIQuery {
    <#
    .SYNOPSIS
        Abstracts logic for which methods, and API calls should be done.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$VaultName,
        [Parameter()]
        [string]$SecretName,
        [Parameter()]
        [object]$SecretValue,
        [Parameter()]
        [hashtable]$Metadata
    )
    try {
        $serverURI = $([HashicorpVaultKV]::VaultServer), $([HashicorpVaultKV]::VaultAPIVersion) -join '/'
        $baseURI = "$serverURI/$VaultName"
        $CallStack = (Get-PSCallStack)[1]
        $CallingCommand = $CallStack.Command
        $CallingVerb, $CallingNoun = ($CallingCommand -split '-')

        if ([HashicorpVaultKV]::KVVersion -eq 'v1') {
            $uri = "$baseURI/$SecretName"
            $listuri = "$baseURI/$SecretName"
        } elseif ([HashicorpVaultKV]::KVVersion -eq 'v2') {
            $uri = "$baseURI/data/$SecretName"
            $listuri = "$baseURI/metadata/$SecretName"
        }

        switch ($CallingVerb) {
            Get {
                $Method = 'GET'
                continue
            }
            Set {
                $Method = 'POST'
                if ($SecretName -match '/') {
                    $Name = $($SecretName -split '/')[-1]
                } else {
                    $Name = $SecretName
                }
                if ($SecretValue.GetType().Name -eq 'Hashtable') {
                    $Body = New-VaultAPIBody -data $SecretValue, $Metadata
                } else {
                    $Body = New-VaultAPIBody -data @{$Name = $SecretValue }, $Metadata
                }
                continue
            }
            Test {
                $method = 'GET'
                $uri = "$serverURI/sys/health", "$serverURI/sys/mounts"
                continue
            }
            Remove {
                $method = 'DELETE'
                # Deletes the secret like a KV version1
                # KV version2 supports versions, which can't be implemented yet.
                # TODO provide a argument for type of action to take on KV v2
                $uri = $listuri
                continue
            }
            Resolve {
                $method = 'LIST'
                $uri = $listuri
                continue
            }
        }

        $VaultSplat = @{
            URI     = $uri
            Method  = $Method
            Headers = New-VaultAPIHeader
        }
        if ($null -ne $body) { $VaultSplat['Body'] = $body }

        if ($method -eq 'List') {
            Invoke-CustomWebRequest @VaultSplat
        } elseif ($CallingVerb -eq 'Test') {
            foreach ($u in $($uri -split ',')) {
                $VaultSplat['URI'] = $u
                Invoke-RestMethod @VaultSplat
            }
        } else {
            Invoke-RestMethod @VaultSplat
        }
    } catch {
        throw
    } finally {
        #Probably unecessary, but precautionary.
        $VaultSplat, $listuri, $uri, $Method, $Metadata, $Body = $null
    }
}
# Public functions
function Get-Secret {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName)]
        [string] $Name,
        [Parameter(ValueFromPipelineByPropertyName)]
        [string] $VaultName,
        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable] $AdditionalParameters
    )
    process {
        $null = Test-SecretVault -VaultName $VaultName -AdditionalParameters $AdditionalParameters
        if ($Name -match '/') {
            $SecretName = $($Name -split '/')[-1]
        } else {
            $SecretName = $Name
        }
        $SecretData = Invoke-VaultAPIQuery -VaultName $VaultName -SecretName $Name
        switch ([HashicorpVaultKV]::KVVersion) {
            'v1' {
                switch ([HashicorpVaultKV]::OutputType) {
                    'PSCredential' {
                        if ($SecretData.data.psobject.properties.Name -notcontains $SecretName) {
                            $Secret = $SecretData.data
                            $SecretObject = [PSCredential]::new($Name, ($Secret | ConvertTo-SecureString -AsPlainText -Force))
                        } else {
                            $Secret = $SecretData.data
                            $SecretObject = [PSCredential]::new($Name, ($Secret.$SecretName | ConvertTo-SecureString -AsPlainText -Force))
                        }
                        continue
                    }
                    'Hashtable' {
                        $Secret = $SecretData.data
                        $Hashtable = @{}
                        $Secret.psobject.properties | ForEach-Object { $Hashtable[$PSItem.name] = $PSItem.value }
                        $SecretObject = $Hashtable
                        continue
                    }
                    default { throw "$([HashicorpVaultKV]::OutputType) OutputType not supported" }
                }
                continue
            }
            'v2' {
                switch ([HashicorpVaultKV]::OutputType) {
                    'PSCredential' {
                        if ($SecretData.data.data.psobject.properties.Name -notcontains $SecretName) {
                            $Secret = $SecretData.data.data
                            $SecretObject = [PSCredential]::new($Name, ($Secret | ConvertTo-SecureString -AsPlainText -Force))
                        } else {
                            $Secret = $SecretData.data.data
                            $SecretObject = [PSCredential]::new($Name, ($Secret.$SecretName | ConvertTo-SecureString -AsPlainText -Force))
                        }
                        continue
                    }
                    'Hashtable' {
                        $Secret = $SecretData.data.data
                        $Hashtable = @{}
                        $Secret.psobject.properties | ForEach-Object { $Hashtable[$PSItem.name] = $PSItem.value }
                        $SecretObject = $Hashtable
                        continue
                    }
                    default { throw "$([HashicorpVaultKV]::OutputType) OutputType not supported" }
                }
                continue
            }
            default { throw "Unknown KeyVaule version" }
        }
        return $SecretObject
    }
}
function Get-SecretInfo {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName)]
        [string] $Filter,
        [Parameter(ValueFromPipelineByPropertyName)]
        [string] $VaultName,
        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable] $AdditionalParameters
    )
    process {
        $null = Test-SecretVault -VaultName $VaultName -AdditionalParameters $AdditionalParameters

        $Filter = "*$Filter"
        $VaultSecrets = Resolve-VaultSecretPath -VaultName $VaultName
        $VaultSecrets |
        Where-Object { $PSItem -like $Filter } |
        ForEach-Object {
            if ([HashicorpVaultKV]::KVVersion -eq 'v1') {
                $Metadata = $null
            } else {
                $vault_metadata = (Invoke-VaultAPIQuery -VaultName $VaultName -SecretName $PSItem).data.metadata
                $Metadata = [Ordered]@{}
                $vault_metadata.psobject.properties | ForEach-Object { $Metadata[$PSItem.Name] = $PSItem.Value }
                $Dictonary = ConvertTo-ReadOnlyDictionary -hashtable $Metadata
            }
            [Microsoft.PowerShell.SecretManagement.SecretInformation]::new(
                "$PSItem",
                "String",
                $VaultName,
                $Dictonary)
        }
    }
}
function Set-Secret {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName)]
        [string] $Name,
        [Parameter(ValueFromPipelineByPropertyName)]
        [object] $Secret,
        [Parameter(ValueFromPipelineByPropertyName)]
        [string] $VaultName,
        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable] $AdditionalParameters,
        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable] $Metadata
    )
    process {
        $null = Test-SecretVault -VaultName $VaultName -AdditionalParameters $AdditionalParameters

        switch ($Secret.GetType()) {
            'String' {
                $SecretValue = $Secret
                continue
            }
            'SecureString' {
                $SecretValue = $Secret | ConvertFrom-SecureString -AsPlainText
                continue
            }
            'PSCredential' {
                $SecretValue = $Secret.Password | ConvertFrom-SecureString -AsPlainText
                continue
            }
            'Hashtable' {
                $SecretValue = $Secret
                continue
            }
            default {
                throw "Unsupported secret type: $($Secret.GetType().Name)"
            }
        }

        $SecretData = Invoke-VaultAPIQuery -VaultName $VaultName -SecretName $Name -SecretValue $SecretValue -Metadata $Metadata

        #$? represents the success/fail of the last execution
        if (-not $?) {
            throw $SecretData
        }
        return $?
    }
}
function Remove-Secret {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName)]
        [string] $Name,
        [Parameter(ValueFromPipelineByPropertyName)]
        [string] $VaultName,
        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable] $AdditionalParameters
    )
    process {
        $null = Test-SecretVault -VaultName $VaultName -AdditionalParameters $AdditionalParameters
        $SecretData = Invoke-VaultAPIQuery -VaultName $VaultName -SecretName $Name

        #$? represents the success/fail of the last execution
        if (-not $?) {
            throw $SecretData
        }
        return $?
    }
}
function Test-SecretVault {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName, Mandatory)]
        [string] $VaultName,
        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable] $AdditionalParameters
    )
    process {
        $ErrorActionPreference = 'STOP'
        Test-VaultVariable -Arguments $AdditionalParameters

        if ($null -eq [HashicorpVaultKV]::VaultServer) {
            [HashicorpVaultKV]::VaultServer = Read-Host -Prompt "Please provide the URL for the HashiCorp Vault (Example: https://myvault.domain.local)"
        }

        if ('None' -eq [HashicorpVaultKV]::VaultAuthType) {
            [HashicorpVaultKV]::VaultAuthType = Read-Host -Prompt "Please provide the AuthType for your HashiCorp Vault. Supported Types: $([HashicorpVaultAuthTypes].GetEnumNames())"
        }

        if ($Null -eq [HashicorpVaultKV]::VaultToken) {
            Write-Verbose "Retrieving a Token for authenticating to Vault"
            Invoke-VaultToken
        }
        if ($Null -eq [HashicorpVaultKV]::OutputType) {
            [HashicorpVaultKV]::OutputType = 'Hashtable'
            Write-Verbose "Setting Default Output Type to Hashtable"
        }

        #The rest runs provided the top 4 items are correct
        try {
            $VaultHealth = (Invoke-VaultAPIQuery -VaultName $VaultName)
        } catch {
            $CheckError = $PSItem.Exception.Response.StatusCode.value__
            $URL = $PSItem.TargetObject.RequestURI.AbsoluteUri
            #Right from https://www.vaultproject.io/api-docs#http-status-codes
            Switch ($CheckError) {
                '400' { Write-Warning -Message "$URL; Invalid request, missing or invalid data" ; continue }
                '403' { Write-Warning -Message "$URL; Forbidden, your authentication details are either incorrect, you don't have access to this feature, or - if CORS is enabled - you made a cross-origin request from an origin that is not allowed to make such requests."; continue }
                '404' { Write-Warning -Message "$URL; Invalid path. This can both mean that the path truly doesn't exist or that you don't have permission to view a specific path."; continue }
                '429' { Write-Warning -Message "$URL; Default return code for health status of standby nodes"; continue }
                '473' { Write-Warning -Message "$URL; Default return code for health status of performance standby nodes"; continue }
                '500' { Write-Warning -Message "$URL; Internal server error. An internal error has occurred, try again later."; continue }
                '502' { Write-Warning -Message "$URL; A request to Vault required Vault making a request to a third party; the third party responded with an error of some kind."; continue }
                '503' { Write-Warning -Message "$URL; Vault is down for maintenance or is currently sealed. Try again later."; continue }
                default { throw "$URL; Something occured while communicating with $([HashicorpVaultKV]::VaultServer)" }
            }
        }
        if ($CheckError -notin @('403', '404')) {
            if ($VaultHealth[0].sealed -eq 'True') {
                Throw "The Hashicorp Vault at $([HashicorpVaultKV]::VaultServer) is sealed"
            }

            #This should return $null if the vault doesn't exist
            if ($VaultHealth[1].Gettype().Name -eq 'PSCustomObject' ) {
                #Some older version may not support this method
                $SelectedVault = $VaultHealth[1].$("$VaultName/")
            } else {
                $SelectedVault = $VaultHealth[1] -Match "$VaultName/"
            }
            if ($null -eq $SelectedVault) {
                #Create Vault if one specified doesn't exist
                $Response = Read-Host -Prompt "$VaultName does not exist on $([HashicorpVaultKV]::VaultServer). Attempt to create it? (Yes/No)"
                if ($Response -imatch '^Y$|^yes$') {
                    New-Vault -VaultName $VaultName -AdditionalParameters $AdditionalParameters
                }
            }
        }

        return $?
    }
}
function Unregister-SecretVault {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName)]
        [string] $VaultName,
        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable] $AdditionalParameters
    )
    process {
        $null = Test-SecretVault -VaultName $VaultName -AdditionalParameters $AdditionalParameters

        $Response = Read-Host -Prompt "Do you want to disable $VaultName on $([HashicorpVaultKV]::VaultServer) as well? (Yes/No) NOTE: This will remove all Secrets"
        if ($Response -imatch '^Y$|^yes$') {
            Remove-Vault -VaultName $VaultName -AdditionalParameters $AdditionalParameters
        }
    }
}
