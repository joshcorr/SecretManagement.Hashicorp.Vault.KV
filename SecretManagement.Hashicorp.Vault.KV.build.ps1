param(
    $ModuleName = 'SecretManagement.Hashicorp.Vault.KV'
)

Write-Verbose "Build script for $ModuleName"

task copy {
    $Version = (Test-ModuleManifest -Path "$PSScriptRoot\$ModuleName\$ModuleName.psd1").Version
    $UserModulePath = [Environment]::GetEnvironmentVariable('PSModulePath') -split [IO.Path]::PathSeparator | Where-Object {$PSItem -notmatch [Environment]::UserName} | Select-Object -First 1
    $Destination = $UserModulePath, $ModuleName, $Version -join [io.path]::DirectorySeparatorChar
    $Source = $PSScriptRoot, $ModuleName, ' ' -join [io.path]::DirectorySeparatorChar
    Copy-Item -Path $Source -Destination $Destination -Force -Recurse -Verbose
}

task remove {
    $Version = (Test-ModuleManifest -Path "$PSScriptRoot\$ModuleName\$ModuleName.psd1").Version
    $UserModulePath = [Environment]::GetEnvironmentVariable('PSModulePath') -split [IO.Path]::PathSeparator | Where-Object {$PSItem -notmatch [Environment]::UserName} | Select-Object -First 1
    $Destination = $UserModulePath, $ModuleName, $Version -join [io.path]::DirectorySeparatorChar
    Remove-Item -Path $Destination -Force -Recurse -Verbose
}

task . copy