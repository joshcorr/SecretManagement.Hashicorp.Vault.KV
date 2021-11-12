BeforeDiscovery {
    $s = [io.path]::DirectorySeparatorChar
    $ModulePath = $PSScriptRoot, '..' -join $s
    $Folder = (Get-Item $ModulePath).FullName
    $File = ($PSCommandPath).Replace('.Tests.ps1', '.psd1').Split($s)[-1]
    $ModuleName = ($PSCommandPath).Replace('.Tests.ps1', '').Split($s)[-1]
    $Path = $Folder, $ModuleName, $File -join $s
    $Extension = Get-ChildItem -Path . -Include *.psm1 -Recurse
    $ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage'
    Import-Module $Extension.FullName
    $commands = Get-Command -Module $Extension.BaseName
}
AfterAll {
    $Extension = Get-ChildItem -Path . -Include *.psm1 -Recurse
    Remove-Module -Name $Extension.BaseName -Force -ErrorAction SilentlyContinue
}
describe "Extension loading" {
    It "Should load the Extension $ModuleName" {
        Get-Module -Name 'SecretManagement.Hashicorp.Vault.KV.Extension' | Should -Not -Be $null
    }
    It "Should have <_> function loaded" -foreach $Commands {
        (Get-Command -Name $PSItem).Name | Should -Be "$PSItem"
    }
}