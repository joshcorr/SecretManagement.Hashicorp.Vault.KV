# For ConvertTo-ReadOnlyDictonary
using namespace System.Collections.ObjectModel
using namespace System.Collections.Generic
# enum and Variables setup for use
$script:HashicorpVaultConfigValues = @('VaultServer', 'VaultAuthType', 'VaultToken', 'VaultAPIVersion', 'KVVersion', 'OutputType', 'Verbose')
$script:AllVariables = @('VaultServer', 'VaultAuthType', 'VaultToken', 'VaultAPIVersion', 'KVVersion', 'OutputType', 'TokenRenewable', 'TokenLifespan', 'TokenType', 'TokenExpireTime', 'Verbose')

enum HashicorpVaultAuthTypes {
    None
    AppRole
    LDAP
    userpass
    Token
    RenewToken
}

$script:HashicorpAuthTypes = @('None', 'AppRole', 'LDAP', 'userpass', 'Token')
[string]$script:VaultServer
[HashicorpVaultAuthTypes]$script:VaultAuthType = 'None'
[Securestring]$script:VaultToken
[string]$script:VaultAPIVersion = 'v1'
[string]$script:KVVersion = 'v2'
[string]$script:OutputType = 'Hashtable'
# Internally used
[bool]$script:TokenRenewable
[double]$script:TokenLifespan
[string]$script:TokenType
[datetime]$script:TokenExpireTime = '01/01/1600'
[bool]$script:Verbose

# Private Functions
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
        $serverURI = $($script:VaultServer), $($script:VaultAPIVersion) -join '/'
        $baseURI = "$serverURI/$VaultName"
        $CallStack = (Get-PSCallStack)[1]
        $CallingCommand = $CallStack.Command
        $CallingVerb, $CallingNoun = ($CallingCommand -split '-')

        if ($script:KVVersion -eq 'v1') {
            $uri = "$baseURI/$SecretName"
            $listuri = "$baseURI/$SecretName"
        } elseif ($script:KVVersion -eq 'v2') {
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
                # Deletes the latest secret version, but does not destory it.
                # KV version2 supports versions, which can't be implemented yet.
                # TODO provide a argument for type of action to take on KV v2
                $uri
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
            $VaultSplat.Remove('Method')
            $VaultSplat['CustomMethod'] = 'LIST'
            Invoke-RestMethod @VaultSplat -ErrorVariable RestError
        } elseif ($CallingVerb -eq 'Test') {
            foreach ($u in $uri) {
                $VaultSplat['URI'] = $u
                Invoke-RestMethod @VaultSplat -ErrorVariable RestError
            }
        } else {
            Invoke-RestMethod @VaultSplat -ErrorVariable RestError
        }
    } catch {
        Write-Error -Message "Received an error: $($RestError.message)"
    } finally {
        #Probably unecessary, but precautionary.
        $VaultSplat, $listuri, $uri, $Method, $Metadata, $Body = $null
    }
}
function Invoke-VaultToken {
    <#
    .SYNOPSIS
        Retrieves Token based on Supported Credential
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [SecureString] $Password,
        [Parameter()]
        [string] $VaultName,
        [Parameter()]
        [hashtable] $AdditionalParameters
    )
    Test-VaultVariable -Arguments $AdditionalParameters
    Write-Verbose "Grabbing token for $VaultName"
    Write-Debug "Current TokenExpireTime: $($script:TokenExpireTime) and is a $(($script:TokenExpireTime).Gettype()) "
    Write-Debug "Is Token renewable? $($script:TokenRenewable)"
    Write-Debug "Token has a lifespan of $($script:TokenLifespan) seconds."
    Write-Debug "Token type is $($script:TokenType)"
    # Retrieve a token
    if ($Null -eq $script:VaultToken) {
        Write-Verbose "Retrieving a Token for authenticating to Vault"
        $RenewToken = $false
        #continue
    } elseif ($Null -ne $script:VaultToken -and $script:TokenExpireTime -lt (Get-date)) {
        # Retrieve a new token if expired
        Write-Verbose "Token Expired at $($script:TokenExpireTime). Retieving a new token"
        $script:VaultToken = $null
        $RenewToken = $false
        #continue
    } elseif ($Null -ne $script:VaultToken -and (New-TimeSpan -Start (Get-date) -End ($script:TokenExpireTime)).Minutes -le 1 -and $script:TokenRenewable) {
        # Renew a new token if about to expire
        Write-Verbose "Token about to Expire at $($script:TokenExpireTime). Renewing the token for $($script:TokenLifespan) seconds."
        $RenewToken = $true
        $script:VaultAuthType = 'RenewToken'
        #continue
    } elseif ($Null -ne $Password -and $Password -eq $script:VaultToken ) {
        Write-Verbose "Force renewing token."
        $RenewToken = $true
        $script:VaultAuthType = 'RenewToken'
    } else {
        Write-Verbose "Token is set to expire at: $($script:TokenExpireTime) and is of $($script:TokenType)"
        return
    }

    $AuthType = $script:VaultAuthType

    if ($Password -and $AuthType -ne 'Token' -and -not $RenewToken) {
        $Login = Read-Host -Prompt "What is the $(if($AuthType -eq 'Approle'){'Role-Id'} else {'Username'})?"
        $Credential = [System.Management.Automation.PSCredential]::new($Login, $Password)
    }
    switch ($script:VaultAuthType) {
        "AppRole" {
            if ( -not $Credential) {
                $Credential = Get-Credential -Message "Please Enter Role-Id and Secret-Id"
            }
            $UserName = $Credential.UserName
            #Following TryParse from https://stackoverflow.com/a/62416925
            $AppRoleResult = [System.Guid]::empty
            if (-not [System.Guid]::TryParse($UserName, [System.Management.Automation.PSReference]$AppRoleResult)) {
                throw "Approle Role-id must be a valid guid"
            }
            $UserLogin = "$($script:VaultServer)/$($script:VaultAPIVersion)/auth/approle/login"
            $UserPassword = "{`"role_id`":`"$UserName`",`"secret_id`":`"$($Credential.GetNetworkCredential().Password)`"}"
            continue
        }
        "LDAP" {
            if (-not $Credential) {
                $Credential = Get-Credential -Message "Please Enter LDAP credentials"
            }
            $UserName = $Credential.UserName
            $UserLogin = "$($script:VaultServer)/$($script:VaultAPIVersion)/auth/ldap/login/$UserName"
            $UserPassword = "{`"password`":`"$($Credential.GetNetworkCredential().Password)`"}"
            continue
        }
        "RenewToken" {
            $UserLogin = "$($script:VaultServer)/$($script:VaultAPIVersion)/auth/token/renew-self"
            $Headers = New-VaultAPIHeader
            continue
        }
        "Token" {
            if ($Password) {
                $script:VaultToken = $Password
            } else {
                $script:VaultToken = (Get-Credential -UserName Token -Message "Please Enter the token").Password
            }
            break
        }
        "userpass" {
            if (-not $Credential) {
                $Credential = Get-Credential -Message "Please Enter UserName and Password credentials"
            }
            $UserName = $Credential.UserName
            $UserLogin = "$($script:VaultServer)/$($script:VaultAPIVersion)/auth/userpass/login/$UserName"
            $UserPassword = "{`"password`":`"$($Credential.GetNetworkCredential().Password)`"}"
            continue
        }
        default {
            throw "This shouldn't be possible please create an issue on  https://github.com/joshcorr/SecretManagement.Hashicorp.Vault.KV"
        }
    }
    try {
        if ($script:VaultAuthType -notin @('Token', 'RenewToken')) {
            $auth = (Invoke-RestMethod -Method POST -Uri $UserLogin -Body $UserPassword -ErrorVariable RestError)
            $auth_info = $auth.auth
            $script:VaultToken = $auth_info.client_token | ConvertTo-SecureString -AsPlainText -Force
        } elseif ($script:VaultAuthType -eq 'RenewToken') {
            $auth = (Invoke-RestMethod -Method POST -Uri $UserLogin -Headers $headers -ErrorVariable RestError)
            $auth_info = $auth.auth
            $script:VaultToken = $auth_info.client_token | ConvertTo-SecureString -AsPlainText -Force
        }

        #Lookup/test token
        $token_uri = "$($script:VaultServer)/$($script:VaultAPIVersion)/auth/token/lookup"
        $token_body = @{'token' = $([PSCredential]::new("token", $($script:VaultToken)).GetNetworkCredential().Password) } | ConvertTo-Json
        $Headers = New-VaultAPIHeader
        $token_info = (Invoke-RestMethod -Method POST -Uri $token_uri -Body $token_body -Headers $headers -ErrorVariable RestError)

        # Storing the information for checking before future calls.
        $script:TokenRenewable = $token_info.data.renewable
        $script:TokenType = $token_info.data.type
        $script:TokenLifespan = $token_info.data.ttl
        $script:TokenExpireTime = $token_info.data.expire_time
    } catch {
        if ($null -ne $RestError.message) {
            throw "Received an error: $($RestError.message)"
        } else {
            throw $PSItem
        }
    } finally {
        if ($RenewToken) {
            $script:VaultAuthType = $AuthType
        }
        $auth, $auth_info, $UserName, $UserPassword, $UserLogin, $Credential, $AppRoleResult, $Password, $Login, $token_body, $token_uri, $token_info, $headers = $null
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
            $serverURI = $($script:VaultServer), $($script:VaultAPIVersion), 'sys/mounts', $VaultName -join '/'

            if ($script:KVVersion -eq 'v1') {
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
        $CombinedData = New-Object -TypeName System.Collections.Hashtable
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
        if ($script:KVVersion -eq 'v1') {
            $Tempbody = $CombinedData
        } elseif ($script:KVVersion -eq 'v2') {
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
        'X-Vault-Token' = $([PSCredential]::new("token", $($script:VaultToken)).GetNetworkCredential().Password)
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
            $serverURI = $($script:VaultServer), $($script:VaultAPIVersion), 'sys/mounts', $VaultName -join '/'
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
        $key = $($k.Key)
        if ($key -notin $script:HashicorpVaultConfigValues) {
            Write-Warning -Message "$key not in accepted config values, skipping"
            continue
        }
        if ($key -eq 'VaultToken') {
            New-Variable -Name $key -Value $($k.Value | ConvertTo-SecureString) -Scope Script
            continue
        }
        if ($null -eq (Get-Variable -Name $key -ErrorAction SilentlyContinue) -or (Get-Variable -Name $key -ErrorAction SilentlyContinue) -ne $key ) {
            New-Variable -Name $key -Value $k.Value -Scope Script -Force
        }
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
        $VerboseSplat = @{Verbose = $AdditionalParameters['Verbose']}
        $null = Test-SecretVault -VaultName $VaultName -AdditionalParameters $AdditionalParameters
        if ($Name -match '/') {
            $SecretName = $($Name -split '/')[-1]
        } else {
            $SecretName = $Name
        }
        $SecretData = Invoke-VaultAPIQuery -VaultName $VaultName -SecretName $Name @VerboseSplat
        #jscpd:ignore-start
        switch ($script:KVVersion) {
            'v1' {
                switch ($script:OutputType) {
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
                        $Hashtable = New-Object -TypeName System.Collections.Hashtable
                        $Secret.psobject.properties | ForEach-Object { $Hashtable[$PSItem.name] = $PSItem.value }
                        $SecretObject = $Hashtable
                        continue
                    }
                    default { throw "$($script:OutputType) OutputType not supported" }
                }
                continue
            }
            'v2' {
                switch ($script:OutputType) {
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
                        $Hashtable = New-Object -TypeName System.Collections.Hashtable
                        $Secret.psobject.properties | ForEach-Object { $Hashtable[$PSItem.name] = $PSItem.value }
                        $SecretObject = $Hashtable
                        continue
                    }
                    default { throw "$($script:OutputType) OutputType not supported" }
                }
                continue
            }
            default { throw "Unknown KeyVaule version" }
        }
        #jscpd:ignore-end
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
        $VerboseSplat = @{Verbose = $AdditionalParameters['Verbose']}
        $null = Test-SecretVault -VaultName $VaultName -AdditionalParameters $AdditionalParameters
        $Filter = "*$Filter"
        $VaultSecrets = Resolve-VaultSecretPath -VaultName $VaultName @VerboseSplat
        $VaultSecrets |
            Where-Object { $PSItem -like $Filter } |
            ForEach-Object {
            if ($script:KVVersion -eq 'v1') {
                $Metadata = $null
            } else {
                $vault_metadata = (Invoke-VaultAPIQuery -VaultName $VaultName -SecretName $PSItem @VerboseSplat).data.metadata
                $Metadata = New-Object -TypeName System.Collections.Hashtable
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
        $VerboseSplat = @{Verbose = $AdditionalParameters['Verbose']}
        $null = Test-SecretVault -VaultName $VaultName -AdditionalParameters $AdditionalParameters
        $SecretData = Invoke-VaultAPIQuery -VaultName $VaultName -SecretName $Name @VerboseSplat

        #$? represents the success/fail of the last execution
        if (-not $?) {
            throw $SecretData
        }
        return $?
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
        $VerboseSplat = @{Verbose = $AdditionalParameters['Verbose']}
        $null = Test-SecretVault -VaultName $VaultName -AdditionalParameters $AdditionalParameters
        $type = $Secret.GetType()
        switch ($Secret.GetType()) {
            'byte' {
                $SecretValue = $Secret
                continue
            }
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
        Write-Verbose "Setting a secret with type: $type"
        $SecretData = Invoke-VaultAPIQuery -VaultName $VaultName -SecretName $Name -SecretValue $SecretValue -Metadata $Metadata @VerboseSplat

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

        # Ensure there is a VaultServer
        if ($null -eq $script:VaultServer) {
            $script:VaultServer = Read-Host -Prompt "Please provide the URL for the HashiCorp Vault (Example: https://myvault.domain.local)"
        }

        # Ensure an authtype is defined
        if ('None' -eq $script:VaultAuthType) {
            $script:VaultAuthType = Read-Host -Prompt "Please provide the AuthType for your HashiCorp Vault. Supported Types: $($script:HashicorpAuthTypes)"
        }

        # Unlock-SecretVault can safely handle ignoring existing tokens.
        Invoke-VaultToken -vaultName $VaultName -AdditionalParameters $AdditionalParameters

        if ($Null -eq $script:OutputType) {
            $script:OutputType = 'Hashtable'
            Write-Verbose "Setting Default Output Type to Hashtable"
        }

        #The rest runs provided the top 4 items are correct
        try {
            Write-Verbose -Message "Checking the health of $VaultName"
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
                default { throw "$URL; Something occured while communicating with $($script:VaultServer)" }
            }
        }
        if ($CheckError -notin @('403', '404')) {
            if ($VaultHealth[0].sealed -eq 'True') {
                Throw "The Hashicorp Vault at $($script:VaultServer) is sealed"
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
                $Response = Read-Host -Prompt "$VaultName does not exist on $($script:VaultServer). Attempt to create it? (Yes/No)"
                if ($Response -imatch '^Y$|^yes$') {
                    New-Vault -VaultName $VaultName -AdditionalParameters $AdditionalParameters
                }
            }
        }
        return $?
    }
}
function Unlock-SecretVault {
    <#
    .SYNOPSIS
        Retrieves Token based on Supported Credential
    #>
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName)]
        [SecureString] $Password,
        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('Name')]
        [Alias('Vault')]
        [string] $VaultName,
        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable] $AdditionalParameters
    )
    process {
        Invoke-VaultToken -Password $Password -VaultName $VaultName -AdditionalParameters $AdditionalParameters
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
        $Response = Read-Host -Prompt "Do you want to disable $VaultName on $($script:VaultServer) as well? (Yes/No) NOTE: This will remove all Secrets"
        if ($Response -imatch '^Y$|^yes$') {
            Write-Verbose "Disabling $VaultName on $($script:VaultServer)"
            Remove-Vault -VaultName $VaultName -AdditionalParameters $AdditionalParameters
        }
    }
}
