# Private Helper Functions
enum HashicorpVaultConfigValues {
    VaultServer
    VaultToken
    VaultAPIVersion
    KVVersion
}
class HashicorpVaultKV {
    static [string] $VaultServer
    static [string] $VaultToken
    static [string] $VaultAPIVersion = 'v1'
    static [string] $KVVersion = 'v2'
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
        [Cmdletbinding()]
        [hashtable]$Data
    )
    if ([HashicorpVaultKV]::KVVersion -eq 'v1') {
        $Tempbody = $Data
    } elseif ([HashicorpVaultKV]::KVVersion -eq 'v2') {
        $Tempbody = @{
            data = $Data
        }
    }
    $OutputBody = $Tempbody | ConvertTo-Json
    return $OutputBody
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
        [Cmdletbinding()]
        [string]$VaultName,
        [Cmdletbinding()]
        [string]$SecretName,
        [Cmdletbinding()]
        [object]$SecretValue
    )
    try {
        $headers = New-VaultAPIHeader
        $serverURI = "$([HashicorpVaultKV]::VaultServer)/$([HashicorpVaultKV]::VaultAPIVersion)"
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
                if ($CallingNoun -eq 'SecretInfo') {
                    $Method = 'LIST'
                    $uri = $listuri
                } else {
                    $Method = 'GET'
                }
            }
            Set {
                $Method = 'POST'
                if ($SecretName -match '/') {
                    $Name = $($SecretName -split '/')[-1]
                } else {
                    $Name = $SecretName
                }
                $Body = New-VaultAPIBody -data @{$Name = $SecretValue }
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
        $VaultSplat, $listuri, $uri, $Method, $Headers, $Body = $null
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
                $Secret = $SecretData.data
                $SecretObject = [PSCredential]::new($Name, ($Secret.$SecretName | ConvertTo-SecureString -AsPlainText -Force))
                continue
            }
            'v2' {
                $Secret = $SecretData.data.data
                $SecretObject = [PSCredential]::new($Name, ($Secret.$SecretName | ConvertTo-SecureString -AsPlainText -Force))
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
        [hashtable] $AdditionalParameters
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
            default {
                throw "Unsupported secret type: $($Secret.GetType().Name)"
            }
        }

        $SecretData = Invoke-VaultAPIQuery -VaultName $VaultName -SecretName $Name -SecretValue $SecretValue

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
        $SelectedVault = $VaultHealth[1].$("$VaultName/")
        if ($null -eq $SelectedVault) {
            Throw "$VaultName does not exist at $([HashicorpVaultKV]::VaultServer)"
        }

        return $?
    }
}
