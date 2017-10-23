Set-StrictMode -Version 4

Function Get-CondensedScriptBlock() {
    <#
    .SYNOPSIS
    Gets a condensed verison of a script block.

    .DESCRIPTION
    Gets a trimmed and condensed version of a script block so it is in its smallest executable form.

    .EXAMPLE
    Get-CondensedScriptBlock -ScriptBlock $block 
    #>      
    [OutputType([ScriptBlock])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, HelpMessage='PowerShell code script block')]
        [ValidateNotNullOrEmpty()]
        [ScriptBlock]$ScriptBlock
    )

    $lines = $ScriptBlock.ToString() -split "`r`n"
    $scriptText = [string[]]@($lines | ForEach-Object { $line = $_.Trim(); if($line -ne ''){$line} } ) -join "`r`n"

    # todo parse statements and flatten into one liner by separating statements with a semicolon
    #$ast = [Management.Automation.Language.Parser]::ParseInput($scriptText, [ref]$tokens, [ref]$errors)

    $scriptBlock = [ScriptBlock]::Create($scriptText)

    return $scriptBlock
}

Function Get-ScriptBlock() {
    <#
    .SYNOPSIS
    Gets a script block from a function body in a script file.

    .DESCRIPTION
    Gets a script block from a function body in a script file.

    .EXAMPLE
    Get-ScriptBlock -Path '.\Detect-CVE-2017-15361-TPM.ps1' -FunctionName 'Test-CVE201715361TPM' 
    #>    
    [OutputType([ScriptBlock])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, HelpMessage='The name of the function')]
        [ValidateNotNullOrEmpty()]
        [string]$FunctionName,

        [Parameter(Mandatory=$true, HelpMessage='The path to file containing the PowerShell function')]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    $scriptBlock = $null

    $Path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)

    if (Test-Path -Path $Path -PathType Leaf) {   
        $tokens = $null
        $errors = $null

        $ast = [Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
        $functionDefinition = $ast.Find({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $args[0].Name -eq $FunctionName }, $true)

        if ($functionDefinition -ne $null) {
            $functionBody = $functionDefinition.Body
            $functionBodyText = $functionBody.Extent.Text
            $functionBodyText = $functionBodyText.Trim('{','}') # function start and end brackets
            $functionBodyLength = $functionBodyText.Length
            $paramBlock = $functionBody.Find({ $args[0] -is [Management.Automation.Language.ParamBlockAst] }, $true)
            $paramBlockText = $paramBlock.Extent.Text
            $paramBlockLength = $paramBlockText.Length
            $paramBlockIndex = $functionBodyText.IndexOf($paramBlockText)    
            $scriptText = ($functionBodyText[($paramBlockIndex+$paramBlockLength)..($functionBodyLength-1)] -join '').Trim()
            $scriptBlock = [ScriptBlock]::Create($scriptText)
        } else {
            throw "function $FunctionName was not found in $Path"
        }
    } else {
        throw "$Path not found"
    }
    return $scriptBlock
}

Function New-NessusAuditFile() {
    <#
    .SYNOPSIS
    Generates a new Nessus audit file based on a script file and function name.

    .DESCRIPTION
    Generates a new Nessus audit file based on a script file and function name.  

    .EXAMPLE
    Get-ScriptBlock -Path '.\Detect-CVE-2017-15361-TPM.ps1' -FunctionName 'Test-CVE201715361TPM' 
    #>    
    [OutputType([void])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, HelpMessage='PowerShell code script block')]
        [ValidateNotNullOrEmpty()]
        [ScriptBlock]$ScriptBlock,

        [Parameter(Mandatory=$true, HelpMessage='The path to save the Nessus audit file to')]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    $template = @'
<check_type	: "Windows" version : "2">
    <group_policy	: "Detects Windows systems that have an enabled Trusted Platform Module (TPM) that is vulnerable to CVE-2017-15361 aka Return of Coppersmith's Attack (ROCA) aka Infineon RSA key generation vulnerability">
        <custom_item>
            type: AUDIT_POWERSHELL
            description: "Detects Windows systems that have an enabled Trusted Platform Module (TPM) that is vulnerable to CVE-2017-15361 aka Return of Coppersmith's Attack (ROCA) aka Infineon RSA key generation vulnerability. Requires that PowerShell 2.0 is installed on the systems that are scanned. Tested on Windows 7 and later."
            info: "
                See the following web sites for more information about the vulnerability:

                    https://www.kb.cert.org/vuls/id/307015
		            https://www.infineon.com/cms/en/product/promopages/rsa-update/
		            https://www.infineon.com/cms/en/product/promopages/rsa-update/rsa-background
		            https://www.infineon.com/cms/en/product/promopages/tpm-update/
		
		        See the following web sites for more information on operating system patches and TPM firmware updates:
		
		            https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/ADV170012
		            https://us.answers.acer.com/app/answers/detail/a_id/51137
		            http://www.fujitsu.com/global/support/products/software/security/products-f/ifsa-201701e.html
		            https://support.hp.com/us-en/document/c05792935
		            https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-hpesbhf03789en_us
		            https://support.lenovo.com/us/en/product_security/LEN-15552
		            https://support.toshiba.com/sscontent?contentId=4015874
                  "
            value_type: POLICY_TEXT
            value_data: "False"
            check_type: CHECK_EQUAL
            powershell_args: "{0}"
            ps_encoded_args: YES
            only_show_cmd_output: NO
            severity: HIGH
        </custom_item>
    </group_policy>
</check_type>
'@

    $Path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)

    $encoded = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ScriptBlock))

    if($encoded.Length -gt 8192) {
        throw ("Encoded script block length of {0} was larger than the allowed maximum of 8192" -f $encoded.Length)
    }

    $template -f $encoded | Out-File -FilePath $Path -Encoding ascii -Force -NoNewline
}

$block = Get-ScriptBlock -Path '.\Detect-CVE-2017-15361-TPM.ps1' -FunctionName 'Test-CVE201715361TPM'
$block = Get-CondensedScriptBlock $block
New-NessusAuditFile -Path '.\Detect-CVE-2017-15361-TPM.audit' -ScriptBlock $block