#Documentation: https://github.com/PowerShell/PSScriptAnalyzer/blob/master/docs/markdown/Invoke-ScriptAnalyzer.md#-settings
#From https://github.com/github/super-linter/blob/master/TEMPLATES/.powershell-psscriptanalyzer.psd1
@{
    #CustomRulePath='path\to\CustomRuleModule.psm1'
    #RecurseCustomRulePath='path\of\customrules'
    Severity            = @(
        'Error'
        'Warning'
    )
    IncludeDefaultRules = ${true}
    ExcludeRules        = @(
        'PSUseShouldProcessForStateChangingFunctions',
        'PSAvoidUsingConvertToSecureStringWithPlainText',
        'PSUseDeclaredVarsMoreThanAssignments',
        'PSUseLiteralInitializerForHashtable'

    )
    #IncludeRules = @(
    #    'PSAvoidUsingWriteHost',
    #    'MyCustomRuleName'
    #)
}