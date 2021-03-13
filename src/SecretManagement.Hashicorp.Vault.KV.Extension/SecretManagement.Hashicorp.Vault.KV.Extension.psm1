# Private Helper Functions
enum HashicorpVaultConfigValues {
    VaultServer
    VaultToken
    VaultAPIVersion
    KVVersion
    Verbose
}
class HashicorpVaultKV {
    static [string] $VaultServer
    static [string] $VaultToken
    static [string] $VaultAPIVersion = 'v1'
    static [string] $KVVersion = 'v2'
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
        if ($null -eq [HashicorpVaultKV]::$($k.key) -or [HashicorpVaultKV]::$($k.key) -ne $($k.key)) {
            [HashicorpVaultKV]::$($k.Key) = $k.Value
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
    try {
        $headers = New-VaultAPIHeader
        $serverURI = $([HashicorpVaultKV]::VaultServer), $([HashicorpVaultKV]::VaultAPIVersion), 'sys/mounts', $VaultName -join '/'

        if ([HashicorpVaultKV]::KVVersion -eq 'v1') {
            $version = '1'
        } else {
            $version = '2'
        }
        $VaultSplat = @{
            URI     = $serverURI
            Method  = 'POST'
            Headers = $Headers
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
        $VaultSplat, $VaultOption, $listuri, $uri, $Method, $Headers, $Body = $null
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
    try {
        $headers = New-VaultAPIHeader
        $serverURI = $([HashicorpVaultKV]::VaultServer), $([HashicorpVaultKV]::VaultAPIVersion), 'sys/mounts', $VaultName -join '/'

        $VaultSplat = @{
            URI     = $serverURI
            Method  = 'DELETE'
            Headers = $Headers
        }

        Invoke-RestMethod @VaultSplat
    } catch {
        throw
    } finally {
        #Probably unecessary, but precautionary.
        $VaultSplat, $serverURI, $Headers = $null
    }
}
function New-VaultAPIHeader {
    <#
    .SYNOPSIS
        Creates a header for an API call
    #>
    @{
        'Content-Type'  = 'application/json'
        'Accept'        = 'application/json'
        'X-Vault-Token' = "$([HashicorpVaultKV]::VaultToken)"
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
        $OutputBody = $Tempbody | ConvertTo-Json
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
        $headers = New-VaultAPIHeader
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
            }
            Test {
                $method = 'GET'
                $uri = "$serverURI/sys/health", "$serverURI/sys/mounts"
            }
            Remove {
                $method = 'DELETE'
                # Deletes the secret like a KV version1
                # KV version2 supports versions, which can't be implemented yet.
                # TODO provide a argument for type of action to take on KV v2
                $uri = $listuri
            }
            Resolve {
                $method = 'LIST'
                $uri = $listuri
            }
        }

        $VaultSplat = @{
            URI     = $uri
            Method  = $Method
            Headers = $Headers
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
        $VaultSplat, $listuri, $uri, $Method, $Headers, $Metadata, $Body = $null
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
                if ($($SecretData.data.psobject.properties | Measure-Object).Count -gt 1) {
                    $Secret = $SecretData.data
                    $SecretObject = [PSCredential]::new($Name, ($Secret | ConvertTo-SecureString -AsPlainText -Force))
                } else {
                    $Secret = $SecretData.data
                    $SecretObject = [PSCredential]::new($Name, ($Secret.$SecretName | ConvertTo-SecureString -AsPlainText -Force))
                }
                continue
            }
            'v2' {
                if ($($SecretData.data.data.psobject.properties | Measure-Object).Count -gt 1) {
                    $Secret = $SecretData.data.data
                    $SecretObject = [PSCredential]::new($Name, ($Secret | ConvertTo-SecureString -AsPlainText -Force))
                } else {
                    $Secret = $SecretData.data.data
                    $SecretObject = [PSCredential]::new($Name, ($Secret.$SecretName | ConvertTo-SecureString -AsPlainText -Force))
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
            }
            [Microsoft.PowerShell.SecretManagement.SecretInformation]::new(
                "$PSItem",
                "String",
                $VaultName)
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
            }
            'SecureString' {
                $SecretValue = $Secret | ConvertFrom-SecureString -AsPlainText
            }
            'PSCredential' {
                $SecretValue = $Secret.Password | ConvertFrom-SecureString -AsPlainText
            }
            'Hashtable' {
                $SecretValue = $Secret
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

        if ($null -eq [HashicorpVaultKV]::VaultToken) {
            [HashicorpVaultKV]::VaultToken = (Read-Host -Prompt "Provide Vault Token" -AsSecureString | ConvertFrom-SecureString -AsPlainText )
        }

        try {
            $VaultHealth = (Invoke-VaultAPIQuery -VaultName $VaultName)
        } catch {
            throw "Something occured while communicating with $([HashicorpVaultKV]::VaultServer). Doublecheck the URL"
        }

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
            $Response = Read-Host -Prompt "$VaultName does not exist on $([HashicorpVaultKV]::VaultServer). Create it? (Yes/No)"
            if ($Response -imatch '^Y$|^yes$') {
                New-Vault -VaultName $VaultName -AdditionalParameters $AdditionalParameters
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
