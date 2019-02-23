# initialize global variable for ini config
$Global:Ini = @{}

# initialize global variable for README
[string]$Global:DBLReadme = ''

# initialize global variable for DefaultConfig INI
[string]$Global:DBLDefaultConfig = ''

# populated with domains currently being blocked using the RuleNamePrefix
[System.Collections.Generic.HashSet[string]]$Global:CurrentBlockList = @()

# populated with domains from updated blocklists
[System.Collections.Generic.HashSet[string]]$Global:NewBlockList = @()

# stores configuration loaded from CacheConfig.xml
$Global:CacheConfig = @{}

# stores data from recent http requests and will be written to CacheConfig.xml
$Global:NewCache = @{}

# Configure https protocol.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Function Clear-DnsBlockListQRPManually
{
    <#
    .SYNOPSIS

    Removes all DnsBlockList QRPs from the registry.

    Warning: This cmdlet will stop the DNS service until QRPs are removed from the registry.

	.DESCRIPTION

    Removes all DnsBlockList QRPs using the following steps. This process is fast since the loaded QRPs do not need to be reindexed.

    Only QRPs using the DnsBlockList prefix will be removed.

		1) Stops the DNS service: Stop-Service DNS

		2) Removes policies in the following registry location using the DnsBlockList Prefix

			"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Policies"

		3) Starts the DNS service: Start-Service DNS

	.OUTPUTS

    System.String[]
    #>

    [CmdletBinding()]
    param(
		[parameter(Mandatory=$true)]
        [switch]
        # Required parameter to proceed with removing all DnsBlockList QRPs.
        $Confirm
		,
		[parameter(Mandatory=$false)]
		[string]
		# Required parameter if configuration file has not been loaded.
		$QrpNamePrefix
    )

	[string]$RemoveQrpPrefix = ''

    if($Confirm){

		if([System.String]::IsNullOrEmpty($QrpNamePrefix) -eq $false){

			$RemoveQrpPrefix = $QrpNamePrefix

		} elseif([System.String]::IsNullOrEmpty($Global:Ini.Script.RuleNamePrefix) -eq $false) {

			$RemoveQrpPrefix = $Global:Ini.Script.RuleNamePrefix

		} else {

			Write-Output '[Error] No QRP rule name prefix specified.'
		}

		if([System.String]::IsNullOrEmpty($RemoveQrpPrefix) -eq $false){

			if(Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Policies'){

				try {

						Stop-Service DNS -ErrorAction Stop
						Push-Location -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Policies' -ErrorAction Stop
						Remove-Item -Path ".\$($RemoveQrpPrefix)*" -Recurse -Force -ErrorAction Stop
						Pop-Location -ErrorAction Stop
						Start-Service DNS -ErrorAction Stop

				} catch {

					$e = $_
					Write-Output $('[Error] Manually removing QRP with prefix {0}' -f $RemoveQrpPrefix)
					Write-Output $('[Error] Exception: {0}' -f $e.Exception.Message)
				}

			} else {

				Write-Output '[Error] Registry location not available'
				Write-Output "[Error] Command: Test-Path `'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Policies`'"
			}
		}
	}

} # End Function Clear-DnsBlockListQRPManually

Function Clear-DnsBlockListQRP
{
    <#
    .SYNOPSIS

    Removes all DnsBlockList QRPs using Remove-DnsServerQueryResolutionPolicy cmdlet.

	.DESCRIPTION

    Removes all DnsBlockList QRPs using Remove-DnsServerQueryResolutionPolicy cmdlet.

    Does NOT Start/Stop the DNS service.

	NOTE: if a large number of QRPs are being removed, this process will take some time since the QRP list must be re-indexed after each deletion.

    .OUTPUTS

    System.String[]
    #>

    [CmdletBinding()]
    param(
		[parameter(Mandatory=$true)]
        [switch]
        # Required parameter to proceed with removing all DnsBlockList QRPs.
        $Confirm
				,
		[parameter(Mandatory=$false)]
		[string]
		# Required parameter if configuration file has not been loaded.
		$QrpNamePrefix
    )

	[string]$RemoveQrpPrefix = ''

    if($Confirm){

		if([System.String]::IsNullOrEmpty($QrpNamePrefix) -eq $false){

			$RemoveQrpPrefix = $QrpNamePrefix

		} elseif([System.String]::IsNullOrEmpty($Global:Ini.Script.RuleNamePrefix) -eq $false) {

			$RemoveQrpPrefix = $Global:Ini.Script.RuleNamePrefix

		} else {

			Write-Output '[Error] No QRP rule name prefix specified.'
		}

		if([System.String]::IsNullOrEmpty($RemoveQrpPrefix) -eq $false){

			$BlockListQRPs = Get-DnsServerQueryResolutionPolicy | Where-Object{ $_.Name.StartsWith($RemoveQrpPrefix) } | Sort-Object ProcessingOrder -Descending

			if($null -ne $BlockListQRPs){

				foreach($QRP in $BlockListQRPs){

					try {

						Remove-DnsServerQueryResolutionPolicy -Name $QRP.Name -Force -ErrorAction Stop

					} catch {

						$e = $_
						Write-Output '[Error] Removing QRP {0}' -f $QRP.Name
						Write-Output '[Error] Exception: {0}' -f $e.Exception.Message
					}
				}

			} else {

				Write-Output '[Info] No QRP using the prefix: {0}' -f $RemoveQrpPrefix
			}
		}
    }

} # End Function Clear-DnsBlockListQRP

Function Get-BlockListDomainsFromFile
{
    <#
    .SYNOPSIS

    Parses the downloaded dns blocklist files.

	.DESCRIPTION

	Parses all of the downloaded dns blocklist files cached in the working directory. If a domain isn't whitelisted it will be added to the NewBlockList global variable.

	A valid line to be parsed must meet the following criteria:
		1) must not begin with a hash (#) sign
		2) must contain a period (.)
		3) must be longer than 2 characters in length

	.OUTPUTS

    Object
    #>

    [CmdletBinding()]
    param( )

	[string[]]$ErrorMsg = @()

	foreach($key in $Global:NewCache.Keys){

		[int]$ParseMethod = 0

		if($Global:Ini.ParseMethod.ContainsKey($key)){

			[int]$ParseMethod = $Global:Ini.ParseMethod[$key]
		}

		if([System.String]::IsNullOrEmpty($Global:NewCache[$key]['File']) -eq $false){

			if(Test-Path -LiteralPath $Global:NewCache[$key]['File']){

				try{

                    $ErrorActionPreference = 'Stop'

					$FileContents = [System.IO.File]::ReadAllLines($Global:NewCache[$key]['File'])

					if($FileContents.Count -gt 0){

                        Write-Verbose -Message "ParseMethod=$($ParseMethod) Key=$($key)"

						[System.Collections.Generic.HashSet[string]]$FileBlockList = @{}

						foreach($line in $FileContents){

							if([System.String]::IsNullOrEmpty($line) -eq $false){

								if($line.Trim().StartsWith('#') -eq $false -and `
								   $line.Contains('.') -eq $true -and `
								   $line.Length -gt 2){

										[string]$LineDomain = Get-DomainFromLine -ParseMethod $ParseMethod -ParseLine $line

										if($Global:Ini.AllowDomainsHash.ContainsKey($LineDomain) -eq $false){

											$FileBlockList.Add($LineDomain) | Out-Null
										}
								}
							}
						}

						if($FileBlockList.Count -gt 0){

							$Global:NewBlockList.UnionWith($FileBlockList) | Out-Null
						}
					}

				} catch {

					$e = $_
					$ErrorMsg += $('[Error][Script] Key: {0}' -f $key)
					$ErrorMsg += $('[Error][Script] File: {0}' -f $Global:NewCache[$key]['File'])
					$ErrorMsg += $('[Error][Script] Exception: {0}' -f $e.Exception.Message)
				}
			}
		}
    }

    [string[]]$BlockDomains = $Global:Ini.BlockDomainsHash.Keys

    $Global:NewBlockList.UnionWith($BlockDomains)

	return $ErrorMsg

} # End Function Get-BlockListDomainsFromFile

Function Write-DnsBlockListNewCache
{
    <#
    .SYNOPSIS

    Exports values in Global:NewCache to CacheConfig.xml

	.DESCRIPTION

	The Global:NewCache variable stores Last-Modified and ETag values from DnsBlockList requests. This xml is imported and it's values are used in future requests to only download updated files.
    #>

    [CmdletBinding()]
    param( )

	[string[]]$ErrorMsg = @()

	$CacheConfigPath = Join-Path -Path $Global:Ini.Script.WorkingDirectory -ChildPath 'CacheConfig.xml'

    try {

        Export-Clixml -LiteralPath $CacheConfigPath -InputObject $Global:NewCache -Force

    } catch {

        $e = $_
        $ErrorMsg += '[Error] Write-DnsBlockListRunningConfig {0}' -f $ActiveConfigPath
		$ErrorMsg += '[Error] Exception: {0}' -f $e.Exception.Message
    }

    return $ErrorMsg

} # End Function Write-DnsBlockListNewCache

Function Get-DnsBlockListChangeList
{
    <#
    .SYNOPSIS

    Compares the NewBlockList with CurrentBlockList to determine what domains to add/remove.

    .OUTPUTS

    System.Collections.Hashtable
    #>

    [CmdletBinding()]
    param( )

	$ChangeList = @{}
	$ChangeList.Add('Add',@())
	$ChangeList.Add('Remove',@())
	$ChangeList.Add('HasChanges',$false)

	[System.Collections.Generic.HashSet[string]]$FullList = @()

	$FullList.UnionWith($Global:CurrentBlockList)
    $FullList.UnionWith($Global:NewBlockList)

    if($Global:Ini.ContainsKey('BlockDomainsHash') -eq $true){

        if($Global:Ini.BlockDomainsHash.Keys.Count -gt 0){

            [string[]]$k = $Global:Ini.BlockDomainsHash.Keys

            $FullList.UnionWith($k) | Out-Null
        }
    }

	foreach($domain in $FullList){

		$OnCurrentList = $Global:CurrentBlockList.Contains($domain)
		$OnNewList = $Global:NewBlockList.Contains($domain)

		if($OnNewList -eq $true -and $OnCurrentList -eq $false){

			if($Global:Ini.AllowDomainsHash.ContainsKey($domain) -eq $false){

				$ChangeList['Add'] += $domain
            }
        }

        if($OnNewList -eq $false -and $OnCurrentList -eq $true){

            $ChangeList['Remove'] += $domain

        }

        if($OnNewList -eq $false -and $OnCurrentList -eq $false){

			if($Global:Ini.AllowDomainsHash.ContainsKey($domain) -eq $false){

				$ChangeList['Add'] += $domain
			}
        }
	}

	if($ChangeList['Add'].Count -gt 0 -or $ChangeList['Remove'].Count -gt 0){

		$ChangeList['HasChanges'] = $true
	}

    return $ChangeList

} # End Function Get-DnsBlockListChangeList

Function Update-DnsBlockListGit
{
    <#
    .SYNOPSIS

    Updates git initiated working directory.

	.DESCRIPTION

	Runs the following GIT commands in the working directory:

		git add -A
        git commit -m "DnsBlockList-PowerShell-Module"
        git push origin master

    .OUTPUTS

    System.Boolean
    #>

    [CmdletBinding()]
    param( )

	[string[]]$ErrorMsg = @()

    try{

        Push-Location -Path $Global:Ini.Script.WorkingDirectory

        $null = & git add -A
        $null = & git commit -m "DnsBlockList-PowerShell-Module"
        $null = & git push origin master

        Pop-Location

    } catch {

        $e = $_
		$ErrorMsg =+ '[Error][Script] Failed to update git.'
		$ErrorMsg =+ '[Error][Script] Exception: {0}' -f $e.Exception.Message
    }

    return $ErrorMsg

} # End Function Update-DnsBlockListGit

Function Get-CurrentQRPDomainBlockList
{
    <#
    .SYNOPSIS

    Parses all Query Resolution Policies (QRP) using the RuleNamePrefix and populates the current DomainBlockList global variable.

	.OUTPUTS

    System.String[]
    #>

    [CmdletBinding()]
    param( )

	[string[]]$ErrorMsg = @()

    try{

        $CurrentQRPs = Get-DnsServerQueryResolutionPolicy | Where-Object{ $_.Name.ToString().StartsWith($Global:Ini.Script.RuleNamePrefix) }

        if($null -ne $CurrentQRPs){

            foreach($QRP in $CurrentQRPs){

				$QrpFqdn = Get-DomainFromCriteria -QRPCriteria $QRP.Criteria.Criteria

                $Global:CurrentBlockList.Add($QrpFqdn) | Out-Null
            }
        }

    } catch {

		$e = $_
		$ErrorMsg += $('[Error][Script] Failed to get current list of QRPs using: RuleNamePrefix = {0}' -f $Global:Ini.Script.RuleNamePrefix)
		$ErrorMsg += $('[Error][Script] Exception: {0}' -f $e.Exception.Message)
	}

    return $ErrorMsg

} # End Function Get-CurrentQRPDomainBlockList

Function Get-DomainFromCriteria
{
    <#
    .SYNOPSIS

    Extracts the domain from the QRP criteria.

    .INPUTS

	System.String

	.OUTPUTS

    System.String
    #>

    [CmdletBinding()]
    param(
			[parameter(Mandatory=$true)]
            [string]
            # QRP criteria
            $QRPCriteria
	)

	$entry = $QRPCriteria.Split(',')[-1]

    if($entry.StartsWith('*')){ $entry = $entry.Substring(1,$entry.Length - 1) }

    if($entry.StartsWith('.')){ $entry = $entry.Substring(1,$entry.Length - 1) }

    if($entry.EndsWith('.')){ $entry = $entry.Substring(0,$entry.Length - 1) }

    return $entry.Trim().ToLower()

} # End Function Get-DomainFromCriteria

Function Get-DnsBlockListQrpName
{
    <#
    .SYNOPSIS

    Returns the QRP name for a DnsBlockList domain.

    .INPUTS

	System.String

	.OUTPUTS

    System.String
    #>

    [CmdletBinding()]
    param(
			[parameter(Mandatory=$true)]
            [string]
            # domain name to build QRP from
            $DomainName
	)

	$QRPName = '{0}{1}' -f $Global:Ini.Script.RuleNamePrefix,$DomainName

    if($QRPName.Length -gt 255){

        $QRPName = $QRPName.Substring(0,255)
    }

	Return $QRPName

} # End Function Get-DnsBlockListQrpName

Function Get-QrpNamesToRemove
{
    <#
    .SYNOPSIS

    Gets the QRP names to be removed ordered by descending ProcessingOrder. Removing QRPs in this order optimizes performance since QRPs with a higher ProcessingOrder must be reindexed.

    .INPUTS

	System.String[]

	.OUTPUTS

    System.String[]
    #>

    [CmdletBinding()]
    param(
			[parameter(Mandatory=$true)]
            [string[]]
            # List of domains with QRPs to remove
            $DomainNameList
	)

	[string[]]$QrpNameList = $DomainNameList | ForEach-Object{ Get-DnsBlockListQrpName -DomainName $_ }

	[System.Collections.Generic.HashSet[string]]$RemoveHashSet = @()

	$RemoveHashSet.UnionWith($QrpNameList)

	[string[]]$RemoveQRPNames = Get-DnsServerQueryResolutionPolicy | Where-Object{ $RemoveHashSet.Contains($_.Name) } | Sort-Object ProcessingOrder -Descending | ForEach-Object{ $_.Name }

	return $RemoveQRPNames

} # End Function Get-QrpNamesToRemove

Function Get-DnsBlockListQRPCommands
{
    <#
    .SYNOPSIS

    Processes the ChangeList hashset to produce QRP Add/Remove commands. If ReadOnly=False, the command will be launched.

    .INPUTS

	System.Collections.Hashtable

	.OUTPUTS

    System.Collections.Hashtable
    #>

    [CmdletBinding()]
    param(
			[parameter(Mandatory=$true)]
            [System.Collections.Hashtable]
            # Hashset containing Add/Remove domains
            $ChangeList
	)

    $ReturnMsg = @{}
	$ReturnMsg.Add('ChangeCommands',@())
	$ReturnMsg.Add('ErrorMsg',@())
	$ReturnMsg.Add('HasError',$false)

	[string[]]$QrpChangeCommands = @('Import-Module DnsServer')

    if($ChangeList['Remove'].Count -gt 0){

        [string[]]$QrpNamesRemove = Get-QrpNamesToRemove -DomainNameList $ChangeList['Remove']

        foreach($QRP in $QrpNamesRemove){

            $QrpChangeCommands += "Remove-DnsServerQueryResolutionPolicy -Name `'$QRP`' -Force"

            if($Global:Ini.Script.ReadOnly -eq $false){

                try {

                    Remove-DnsServerQueryResolutionPolicy -Name $QRP -Force

                } catch {

                    $e = $_
                    $ReturnMsg.HasError = $true
                    $ReturnMsg.ErrorMsg += '[Error][Script] Remove-DnsServerQueryResolutionPolicy -Name {0} -Force' -f $QRP
                    $ReturnMsg.ErrorMsg += '[Error][Script] Exception: {0}' -f $e.Exception.Message
                }
            }
        }
    }

    if($ChangeList['Add'].Count -gt 0){

        foreach($Domain in $ChangeList['Add']){

            $QrpName = Get-DnsBlockListQrpName -DomainName $Domain

            $QrpChangeCommands += "Add-DnsServerQueryResolutionPolicy -Name `'$QrpName`' -Action $($Global:Ini.Script.DnsResponse) -Fqdn `'EQ,$($Domain)`'"

            if($Global:Ini.Script.ReadOnly -eq $false){

                try{

                    Add-DnsServerQueryResolutionPolicy -Name $QrpName -Action $Global:Ini.Script.DnsResponse -Fqdn "EQ,$($Domain)"

                } catch {

                    $e = $_
                    $ReturnMsg.HasError = $true
                    $ReturnMsg.ErrorMsg += '[Error][Script] Add-DnsServerQueryResolutionPolicy -Name {0} -Action {1} -Fqdn "EQ,{2}"' -f $QrpName,$Global:Ini.Script.DnsResponse,$Domain
                    $ReturnMsg.ErrorMsg += '[Error][Script] Exception: {0}' -f $e.Exception.Message
                }
            }
        }
    }

	$ReturnMsg.ChangeCommands = $QrpChangeCommands

    return $ReturnMsg

} # End Function Get-DnsBlockListQRPCommands

Function Write-DnsBlockListQRPCommands
{
    <#
    .SYNOPSIS

    Writes the QRP Add/Remove commands to Update-DnsServerQRP.ps1

    .INPUTS

	System.String[]

	.OUTPUTS

    System.String[]
    #>

    [CmdletBinding()]
    param(
			[parameter(Mandatory=$true)]
            [System.String[]]
            # String array containing QRP change commands.
            $ChangeCommands
	)

    [string[]]$ErrorMsg = @()

    if($ChangeCommands.Count -gt 1){

        try{

            [System.IO.File]::WriteAllLines($Global:Ini.Script.ChangeCmdFile, $ChangeCommands, [System.Text.Encoding]::ASCII) | Out-Null

        } catch {

			$e = $_
            $ErrorMsg += '[Error][Script] Failed writing change commands to {0}' -f $Global:Ini.Script.ChangeCmdFile
			$ErrorMsg += '[Error][Script] Exception: {0}' -f $e.Exception.Message
        }
    }

	return $ErrorMsg

} # End Function Write-DnsBlockListQRPCommands

Function Invoke-DnsBlockList
{
    <#
    .SYNOPSIS

    Launches DnsBlockList PowerShell module which was created to automate the aggregation of DNS blocklists for the creation of Query Resolution Policies (QRP) on a Microsoft DNS server.

	.DESCRIPTION

	The DnsBlockList module first reads and validates the provided configuration file. Then the Query Resolution Policies (QRP) are processed to get domains currently loaded. Next, each [BlockListUrl] is queried for changes and updated files are downloaded to the [WorkingDirectory] as a .DnsBlockListCache file. All files are processed and the aggregated list of domains get compared with those currently loaded to produce the add/remove commands in Update-DnsServerQRP.ps1.

    .INPUTS

    System.String

    .OUTPUTS

    System.String[]

    #>

    [CmdletBinding()]
    [OutputType('System.String[]')]
    param(
            [parameter(Mandatory=$true)]
			[ValidateScript({Test-Path -LiteralPath $_})]
            [string]
            # Path to configuration file.
            $Configuration
    )

    # Reset variables
    [System.Collections.Generic.HashSet[string]]$Global:CurrentBlockList = @()
    [System.Collections.Generic.HashSet[string]]$Global:NewBlockList = @()
    $Global:CacheConfig = @{}
    $Global:NewCache = @{}

	$Global:Ini = Get-IniConfig -Path $Configuration

    [bool]$ConfigFileError = Confirm-DnsBlockListSettings

	if($ConfigFileError -eq $false){

		$n = 0

		[string[]]$ReturnMsg = @()

		do{

			$n++

			if($ReturnMsg.Count -gt 0){

				$n = 1000
			}

            Write-Verbose -Message "Invoke-DnsBlockList: n=$($n)"

			switch($n)
			{
				1 {
						$ReturnMsg = Get-CurrentQRPDomainBlockList
				}
				2 {
                        $ReturnMsg = Get-DnsBlockListWebFiles
                }
                3 {
                        $ReturnMsg = Get-BlockListDomainsFromFile
				}
				4 {
						$ChangeObj = Get-DnsBlockListChangeList

						Publish-QRPStats -Changes $ChangeObj

						if($ChangeObj.HasChanges){

							$CmdObj = Get-DnsBlockListQRPCommands -ChangeList $ChangeObj

							if($CmdObj.HasError -eq $false){

								if($CmdObj.ChangeCommands.Count -gt 1){

									$ReturnMsg += Write-DnsBlockListQRPCommands -ChangeCommands $CmdObj.ChangeCommands
								}

							} else {

								$ReturnMsg += $CmdObj.ErrorMsg
							}
						}
				}
				5 {
						$ReturnMsg = Write-DnsBlockListNewCache
				}
				6 {
						if($Global:Ini.Script.UpdateGit){

							$ReturnMsg = Update-DnsBlockListGit
						}
				}
				default {

						if($ReturnMsg.Count -gt 0){

							$Global:Ini['Script']['HasError'] = $true

							[string[]]$ReturnMsg = @('[Error][Script] Terminating error.') + $ReturnMsg

							$Global:Ini['Script'].Add('ErrorMsg',$ReturnMsg)

							$ReturnMsg | ForEach-Object{ Write-Output $_ }

							Submit-Alert -Message $ReturnMsg -HasError

						} else {

                            $Global:Ini['Script']['HasError'] = $false

                            $Global:Ini.Script.Stats | ForEach-Object{ Write-Output $_ }

							Submit-Alert -Message $Global:Ini.Script.Stats
						}

						$n = 0
				}
			}

		} while($n -gt 0)

    } else {

        $Global:Ini.Script.ErrorMsg | ForEach-Object{ Write-Output $_ }

        Submit-Alert -Message $Global:Ini.Script.ErrorMsg -HasError
    }

} # End Function Invoke-DnsBlockList

Function Submit-Alert
{
    <#
    .SYNOPSIS

    Submits alert to Event Log or via SMTP.
    #>

    [CmdletBinding()]
    param(
            [parameter(Mandatory=$true)]
            [System.String[]]
            # Message body.
            $Message
            ,
            [parameter(Mandatory=$false)]
            [switch]
            # Signifies an error.
            $HasError
    )

    if($Global:Ini.Alert.Method -match "^(?i)(.*)WinEvent(.*)$"){

        if($HasError){

            Write-EventAlert -Message $Message -HasError

        } else {

            Write-EventAlert -Message $Message
        }
    }

    if($Global:Ini.Alert.Method -match "^(?i)(.*)Smtp(.*)$"){

        if($HasError){

            Send-SmtpAlert -Message $Message -HasError

        } else {

			Send-SmtpAlert -Message $Message
        }
    }

} # End Function Submit-Alert

Function Write-EventAlert
{
    <#
    .SYNOPSIS

    Writes alert to windows event log.
    #>

    [CmdletBinding()]
    param(
            [parameter(Mandatory=$true)]
            [System.String[]]
            # Message for alert.
            $Message
            ,
            [parameter(Mandatory=$false)]
            [switch]
            # Signifies an error.
            $HasError
    )

    $EventEntryType = 'Information'
    $EventId = $Global:Ini.WinEvent.InfoEventId

    if($HasError){

        $EventEntryType = 'Error'
        $EventId = $Global:Ini.WinEvent.ErrorEventId
    }

    try {

            Write-EventLog -LogName $Global:Ini.WinEvent.Logname `
                           -Source $Global:Ini.WinEvent.Source `
                           -EntryType $EventEntryType `
                           -EventId $EventId `
                           -Message $($Message -Join [System.Environment]::NewLine) `
                           -ErrorAction Stop

    } catch {

        $e = $_
        Write-Output '[Error][Script] Event log write failed.'
		Write-Output $('[Error][Script] Exception: {0}' -f $e.Exception.Message)
    }


} # End Function Write-EventAlert

Function Send-SmtpAlert
{
    <#
    .SYNOPSIS

    Sends alert via SMTP.
    #>

    [CmdletBinding()]
    param(
            [parameter(Mandatory=$true)]
            [System.String[]]
            # Message body.
            $Message
            ,
            [parameter(Mandatory=$false)]
            [switch]
            # Signifies an error
            $HasError
    )

    $EmailSubject = $Global:Ini.Smtp.Subject

    if($HasError){

        $EmailSubject = '[Error] {0}' -f $EmailSubject
    }

    try {

        if([System.String]::IsNullOrEmpty($Global:Ini.Smtp.CredentialXml)){

            Send-MailMessage -To $Global:Ini.Smtp.To `
                             -From $Global:Ini.Smtp.From `
                             -Subject $EmailSubject `
                             -SmtpServer $Global:Ini.Smtp.Server `
                             -Port $Global:Ini.Smtp.Port `
                             -Body $($Message -Join [System.Environment]::NewLine) `
                             -UseSsl `
                             -ErrorAction Stop

        } else {

            $creds = Import-Clixml -LiteralPath $Global:Ini.Smtp.CredentialXml

            Send-MailMessage -To $Global:Ini.Smtp.To `
                             -From $Global:Ini.Smtp.From `
                             -Subject $EmailSubject `
                             -SmtpServer $Global:Ini.Smtp.Server `
                             -Port $Global:Ini.Smtp.Port `
                             -Body $($Message -Join [System.Environment]::NewLine) `
                             -Credential $creds `
                             -UseSsl `
                             -ErrorAction Stop

            Remove-Variable -Name creds
        }

    } catch {

        $e = $_
        Write-Output '[Error][Script] Smtp send failed.'
		Write-Output $('[Error][Script] Exception: {0}' -f $e.Exception.Message)
    }

} # End Function Send-SmtpAlert

Function Get-IniConfig
{
    <#
    .SYNOPSIS

    Parses the configuration file into a hashtable.

    .INPUTS

    System.String

    .OUTPUTS

    System.Collections.Hashtable

    .LINK

    https://blogs.technet.microsoft.com/heyscriptingguy/2011/08/20/use-powershell-to-work-with-any-ini-file/
    #>

    [CmdletBinding()]
    [OutputType('System.Collections.Hashtable')]
    param(
            [parameter(Mandatory=$true)]
            [ValidateScript({Test-Path -LiteralPath $_})]
            [string]
            # Path to configuration file.
            $Path
    )

    $config = @{}

    switch -regex -file $Path
    {
        "^.*\[(.+)\].*$" # Section
        {
            $section = $matches[1]

            if($section.ToString().Trim().StartsWith('#') -eq $false){

                $config.Add($section.Trim(),@{})
            }
        }

        "(.+?)\s*=(.*)" # Key
        {
            $name,$value = $matches[1..2]

            if($name.ToString().Trim().StartsWith('#') -eq $false){

                $config[$section].Add($name.Trim(), $value.Trim())
            }
        }
    }

    if([System.String]::IsNullOrEmpty($config['Script'])){

        $config.Add('Script',@{})
    }

    $config['Script'].Add('ConfigPath',(Get-Item $Path).FullName)

    $config['Script'].Add('StartTS', (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))

    return $config

} # End Function Get-IniConfig

Function Confirm-DnsBlockListSettings
{
    <#
    .SYNOPSIS

    Validates DnsBlockList settings.

    .OUTPUTS

    System.Boolean
    #>

    [CmdletBinding()]
    param( )

	$i = 0

    [string[]]$ErrorMsg = @()

    do{

        $i++

        if($ErrorMsg.Count -gt 0){

            $i = 1000
        }

        Write-Verbose -Message "Confirm-DnsBlockListSettings: i=$($i)"

        switch($i)
        {
            1 {     # BEGIN validate [INI]

                    try {

                        $foo = Get-Variable -Name Ini -Scope Global

                    } catch {

                        $ErrorMsg += '[Error] No configuration file.'
                    }

                    if($ErrorMsg.Count -eq 0){

                        [string[]]$ConfigSections = 'Script','BlockListUrl','AllowDomains','BlockDomains','ParseMethod','Alert','Smtp','WinEvent'

                        foreach($section in $ConfigSections){

                            if($Global:Ini.ContainsKey($section) -eq $false){

                                $Global:Ini.Add($section,@{})

                            } else {

                                if($Global:Ini[$section].GetType().Name -ne 'Hashtable'){

                                    $ErrorMsg += $('[Error][Script] unknown type: {0}' -f $section)
                                }
                            }
                        }
                    }

            }       # END validate [INI]

			2 {     # BEGIN validate [Script] RuleNamePrefix

                    if($Global:Ini.Script.ContainsKey('RuleNamePrefix') -eq $true){

                        if([System.String]::IsNullOrEmpty($Global:Ini.Script.RuleNamePrefix)){

                            $ErrorMsg += '[Error][Script] RuleNamePrefix not specified.'
                        }

                    } else {

                        $ErrorMsg += '[Error][Script] RuleNamePrefix not specified.'
                    }

            }       # END validate [Script] RuleNamePrefix

            3 {     # BEGIN validate [Script] DnsResponse

                    if($Global:Ini.Script.ContainsKey('DnsResponse') -eq $true){

                        if([System.String]::IsNullOrEmpty($Global:Ini.Script.DnsResponse) -eq $false){

                            if($Global:Ini.Script.DnsResponse -notmatch "^(?i)(Allow|Deny|Ignore)$"){

                                $ErrorMsg += '[Error][Script] DnsResponse not valid.'
                            }

                        } else {

                            $ErrorMsg += '[Error][Script] DnsResponse not specified.'
                        }

                    } else {

                        $ErrorMsg += '[Error][Script] DnsResponse not specified.'
                    }

            }       # END validate [Script] DnsResponse

			4 {     # BEGIN validate [Script] WorkingDirectory

                    if($Global:Ini.Script.ContainsKey('WorkingDirectory') -eq $true){

                        if([System.String]::IsNullOrEmpty($Global:Ini.Script.WorkingDirectory) -eq $false){

                            try {

                                $WDItem = Get-Item -LiteralPath $Global:Ini.Script.WorkingDirectory -ErrorAction Stop

                                if($WDItem.PSIsContainer -eq $false){

                                    $ErrorMsg += '[Error][Script] WorkingDirectory not valid.'
                                }

                            } catch {

                                $e = $_
                                $ErrorMsg += '[Error][Script] WorkingDirectory not valid.'
                                $ErrorMsg += $('[Error][Script] Exception: {0}' -f $e.Exception.Message)
                            }

                            if($ErrorMsg.Count -eq 0){

                                try {

                                    $TestFile = New-Item -Path $Global:Ini.Script.WorkingDirectory -Name "$(([System.Guid]::NewGuid()).Guid).test" -Type File
                                    Remove-Item $TestFile

                                } catch {

                                    $e = $_
                                    $ErrorMsg += '[Error][Script] WorkingDirectory failed to create/delete test file.'
                                    $ErrorMsg += $('[Error][Script] Exception: {0}' -f $e.Exception.Message)
                                }
                            }

                        } else {

                            $ErrorMsg += '[Error][Script] WorkingDirectory not specified.'
                        }

                    } else {

                        $ErrorMsg += '[Error][Script] WorkingDirectory not specified.'
                    }

            }       # END validate [Script] WorkingDirectory

			5 {     # BEGIN validate [Script] ReadOnly

                    if($Global:Ini.Script.ContainsKey('ReadOnly') -eq $true){

                        if([System.String]::IsNullOrEmpty($Global:Ini.Script.ReadOnly) -eq $false){

                            if($Global:Ini.Script.ReadOnly -match "^(?i)(false)$"){

                                $Global:Ini.Script.ReadOnly = $false

                            } else {

                                $Global:Ini.Script.ReadOnly = $true
                            }

                        } else {

                            $Global:Ini.Script.ReadOnly = $true
                        }

                    } else {

                        $Global:Ini.Script.Add('ReadOnly',$true)
                    }

            }       # END validate [Script] ReadOnly

			6 {     # BEGIN validate [Script] UpdateGit

                    if($Global:Ini.Script.ContainsKey('UpdateGit') -eq $true){

                        if([System.String]::IsNullOrEmpty($Global:Ini.Script.UpdateGit) -eq $false){

                            if($Global:Ini.Script.UpdateGit -match "^(?i)(true)$"){

                                $Global:Ini.Script.UpdateGit = $true

                            } else {

                                $Global:Ini.Script.UpdateGit = $false
                            }

                        } else {

                            $Global:Ini.Script.UpdateGit = $false
                        }

                    } else {

                        $Global:Ini.Script.Add('UpdateGit',$false)
                    }

            }       # END validate [Script] UpdateGit

            7 {     # BEGIN validate [BlockListUrl]

                    if($Global:Ini.BlockListUrl.Count -gt 0){

                        $Keys = $Global:Ini.BlockListUrl.Keys | Sort-Object

                        foreach($key in $Keys){

                            if($ErrorMsg.Count -eq 0){

                                try{

                                    [System.Uri]$URI = [System.Uri]$($Global:Ini.BlockListUrl[$key])

                                } catch {

                                    $e = $_

                                    $ErrorMsg += $('[Error][BlockListUrl] {0} not valid.' -f $Global:Ini.BlockListUrl[$key])
                                    $ErrorMsg += $('[Error][BlockListUrl] {0} = {1}' -f $key,$Global:Ini.BlockListUrl[$key])
                                    $ErrorMsg += $('[Error][BlockListUrl] Exception: {0}' -f $e.Exception.Message)
                                }
                            }
                        }
                    }

            }       # END validate [BlockListUrl]

            8 {     # BEGIN validate [AllowDomains]

                    if($Global:Ini.AllowDomains.Count -gt 0){

                        $Keys = $Global:Ini.AllowDomains.Keys | Sort-Object

                        $AllowDomainsHash = @{}

                        foreach($key in $Keys){

                            if($ErrorMsg.Count -eq 0){

                                try{

                                    [System.Uri]$URI = [System.Uri]$('http://{0}/' -f $Global:Ini.AllowDomains[$key])

                                    if($AllowDomainsHash.ContainsKey($Global:Ini.AllowDomains[$key]) -eq $false){

                                        $AllowDomainsHash.Add($Global:Ini.AllowDomains[$key],1)
                                    }

                                } catch {

                                    $e = $_
                                    $ErrorMsg += $('[Error][AllowDomains] {0} not valid.' -f $Global:Ini.AllowDomains[$key])
                                    $ErrorMsg += $('[Error][AllowDomains] {0} = {1}' -f $key,$Global:Ini.AllowDomains[$key])
                                    $ErrorMsg += $('[Error][AllowDomains] Exception: {0}' -f $e.Exception.Message)
                                }
                            }
                        }

                        if($ErrorMsg.Count -eq 0){

                            $Global:Ini.Add('AllowDomainsHash',$AllowDomainsHash)
                        }

                    } else {

                        $Global:Ini.Add('AllowDomainsHash',@{})
                    }

            }       # END validate [AllowDomains]

			9 {     # BEGIN validate [BlockDomains]

                    if($Global:Ini.BlockDomains.Count -gt 0){

                        $Keys = $Global:Ini.BlockDomains.Keys | Sort-Object

                        $BlockDomainsHash = @{}

                        foreach($key in $Keys){

                            if($ErrorMsg.Count -eq 0){

                                try{

                                    [System.Uri]$URI = [System.Uri]$('http://{0}/' -f $Global:Ini.BlockDomains[$key])

                                    if($BlockDomainsHash.ContainsKey($Global:Ini.BlockDomains[$key]) -eq $false){

                                        if($Global:Ini.AllowDomainsHash.ContainsKey($Global:Ini.BlockDomains[$key]) -eq $false){

                                            $BlockDomainsHash.Add($Global:Ini.BlockDomains[$key],1)
                                        }
                                    }

                                } catch {

                                    $e = $_
                                    $ErrorMsg += $('[Error][BlockDomains] {0} not valid.' -f $Global:Ini.BlockDomains[$key])
                                    $ErrorMsg += $('[Error][BlockDomains] {0} = {1}' -f $key,$Global:Ini.BlockDomains[$key])
                                    $ErrorMsg += $('[Error][BlockDomains] {0}' -f $e.Exception.Message)
                                }
                            }
                        }

                        if($ErrorMsg.Count -eq 0){

                            $Global:Ini.Add('BlockDomainsHash',$BlockDomainsHash)
                        }

                    } else {

                        $Global:Ini.Add('BlockDomainsHash',@{})
                    }

            }       # END validate [BlockDomains]

			10 {	# BEGIN validate [ParseMethod]

                    if($Global:Ini.ParseMethod.Count -gt 0){

                        foreach($key in $Global:Ini.ParseMethod.Keys){

                            [int]$DefaultParse = 0

                            if([System.Int32]::TryParse($Global:Ini.ParseMethod[$key], [ref]$DefaultParse)){

                                if($DefaultParse -le 0){

                                    $ErrorMsg += $('[Error][ParseMethod] {0} Value must be a number greater than zero.' -f $Global:Ini.ParseMethod[$key])
                                }
                            }

                            if($Global:Ini.BlockListUrl.ContainsKey($key) -eq $false){

                                $ErrorMsg += $('[Error][ParseMethod] {0} must correspond to a BlockListUrl key.' -f $key)
                            }
                        }
                    }

			}		# END validate [ParseMethod]

			11 {	# BEGIN validate Eventlog source

					try{

						if([System.Diagnostics.EventLog]::SourceExists('DnsBlockList') -eq $false){

							$ErrorMsg += '[Error][Script] DnsBlockList event source does not exist.'
							$ErrorMsg += '[Error][Script] Run the following command as Administrator:'
							$ErrorMsg += '                New-EventLog -LogName Application -Source DnsBlockList'
						}

					} catch {

						$e = $_
						$ErrorMsg += '[Error][WinEvent] Source does not exist.'
						$ErrorMsg += '[Error][WinEvent] Exception: {0}' -f $e.Exception.Message
					}

            }		# END validate Eventlog source

            12 {	# BEGIN validate DNS service

					if((Get-Service -Name "DNS").Status -ne 'Running'){

						$ErrorMsg += '[Error][Script] DNS Server Service is not Running or DNS role is not installed.'
					}

            }		# END validate DNS service

            13 {	# BEGIN DNS Server Management Module

					if($null -eq $(Get-Module -Name DnsServer)){

                        $ErrorMsg += '[Error][Script] Failed to load DNS Server Management Module (DnsServer).'
					}

            }		# END DNS Server Management Module

			14 {	# BEGIN validate Cache config import

					$CacheConfigPath = Join-Path -Path $Global:Ini.Script.WorkingDirectory -ChildPath 'CacheConfig.xml'

					if(Test-Path -LiteralPath $CacheConfigPath){

						try {

							$Global:CacheConfig = Import-Clixml -LiteralPath $CacheConfigPath

						} catch {

							$ErrorMsg += '[Error][Script] Failed to import {0}' -f $CacheConfigPath
						}
                    }

            }		# END validate Cache config import

            15 {	# BEGIN validate Cache Config variable

					foreach($key in $Global:Ini.BlockListUrl.Keys){

						if($Global:CacheConfig.ContainsKey($key) -eq $true -and $Global:Ini.BlockListUrl.ContainsKey($key) -eq $true){

							if($Global:CacheConfig[$key].Url -ne $Global:Ini.BlockListUrl[$key]){

								if(Test-Path -LiteralPath $Global:CacheConfig[$key].File){

									Remove-Item -LiteralPath $Global:CacheConfig[$key].File
								}

                                $Global:CacheConfig[$key].File = ''
                                $Global:CacheConfig[$key].Url = ''
								$Global:CacheConfig[$key].etag = ''
								$Global:CacheConfig[$key].LastModified = ''
                            }
                        }
					}

			}		# END validate Cache Config variable

			16 {	# BEGIN validate Git

					if($Global:Ini.Script.UpdateGit){

						try {

							Push-Location -LiteralPath $Global:Ini.Script.WorkingDirectory

							& git --version | Out-Null

							Pop-Location

						} catch {

							$e = $_
							$ErrorMsg += '[Error][Script] git install verification failed.'
							$ErrorMsg += $('[Error][Script] Exception: {0}' -f $e.Exception.Message)
						}
					}

			}		# END validate Git

			17 {	# BEGIN validate change cmd file

					$ChangeCmdFile = Join-Path -Path $Global:Ini.Script.WorkingDirectory -ChildPath 'Update-DnsServerQRP.ps1'

					if(Test-Path -LiteralPath $ChangeCmdFile){

						Clear-Content -LiteralPath $ChangeCmdFile

					} else {

						New-Item -Path $ChangeCmdFile -Type File | Out-Null
					}

                    if($Global:Ini.Script.ContainsKey('ChangeCmdFile') -eq $false){

						$Global:Ini.Script.Add('ChangeCmdFile',$ChangeCmdFile)

					} else {

						$Global:Ini.Script.ChangeCmdFile = $ChangeCmdFile
					}

			}		# END validate change cmd file

			18 {    # BEGIN validate [Alert] Method

                    if($Global:Ini.Alert.ContainsKey('Method') -eq $true){

                        if([System.String]::IsNullOrEmpty($Global:Ini.Alert.Method) -eq $false){

                            if($Global:Ini.Alert.Method -notmatch "^(?i)Smtp|WinEvent|stdout$"){

                                $ErrorMsg += '[Error][Alert] Method not valid.'
                            }

                        } else {

                            $Global:Ini.Alert.Method = 'stdout'
                        }

                    } else {

                        $Global:Ini.Alert.Add('Method','stdout')
                    }

            }       # END validate [Alert] Method

            19 {    # BEGIN validate [SMTP] To

                    if($Global:Ini.Alert.Method -match "^(?i)(.*)Smtp(.*)$"){

                        if($Global:Ini.Smtp.ContainsKey('To') -eq $true){

                            if([System.String]::IsNullOrEmpty($Global:Ini.Smtp.To) -eq $false){

                                try {

                                    $smtpTo = [System.Net.Mail.MailAddress]::New($Global:Ini.Smtp.To)

                                } catch {

                                    $ErrorMsg += '[Error][SMTP] TO not valid.'
                                }

                            } else {

                                $ErrorMsg += '[Error][SMTP] TO not specified.'
                            }

                        } else {

                            $ErrorMsg += '[Error][SMTP] TO not specified.'
                        }
                    }

            }       # END validate [SMTP] To

            20 {    # BEGIN validate [SMTP] From

                    if($Global:Ini.Alert.Method -match "^(?i)(.*)Smtp(.*)$"){

                        if($Global:Ini.Smtp.ContainsKey('From') -eq $true){

                            if([System.String]::IsNullOrEmpty($Global:Ini.Smtp.From) -eq $false){

                                try {

                                    $smtpFrom = [System.Net.Mail.MailAddress]::new($Global:Ini.Smtp.From)

                                } catch {

                                    $ErrorMsg += '[Error][SMTP] FROM not valid.'
                                }

                            } else {

                                $ErrorMsg += '[Error][SMTP] FROM not specified.'
                            }

                        } else {

                            $ErrorMsg += '[Error][SMTP] FROM not specified.'
                        }
                    }

            }       # END validate [SMTP] From

            21 {    # BEGIN validate [SMTP] Subject

                    if($Global:Ini.Alert.Method -match "^(?i)(.*)Smtp(.*)$"){

                        if($Global:Ini.Smtp.ContainsKey('Subject') -eq $true){

                            if([System.String]::IsNullOrEmpty($Global:Ini.Smtp.Subject) -eq $false){

                                try {

                                    $msg = [System.Net.Mail.MailMessage]::new()
                                    $msg.Subject = $Global:Ini.Smtp.Subject
                                    $msg.Dispose()
                                    Remove-Variable -Name msg

                                } catch {

                                    $ErrorMsg += '[Error][SMTP] SUBJECT not valid.'
                                }

                            } else {

                                $ErrorMsg += '[Error][SMTP] SUBJECT not specified.'
                            }

                        } else {

                            $ErrorMsg += '[Error][SMTP] SUBJECT not specified.'
                        }
                    }

            }       # END validate [SMTP] Subject

            22 {    # BEGIN validate [SMTP] Port

                    if($Global:Ini.Alert.Method -match "^(?i)(.*)Smtp(.*)$"){

                        if($Global:Ini.Smtp.ContainsKey('Port') -eq $true){

                            if([System.String]::IsNullOrEmpty($Global:Ini.Smtp.Port) -eq $false){

                                [int]$intPort = 0

                                if([System.Int32]::TryParse($Global:Ini.Smtp.Port, [ref]$intPort)){

                                    if($intPort -gt 0){

                                        [int]$Global:Ini.Smtp.Port = $intPort

                                    } else {

                                        $ErrorMsg += '[Error][SMTP] PORT must be a positive number.'
                                    }

                                } else {

                                    $ErrorMsg += '[Error][SMTP] PORT must be a positive number.'
                                }

                            } else {

                                $ErrorMsg += '[Error][SMTP] PORT not specified.'
                            }

                        } else {

                            $ErrorMsg += '[Error][SMTP] PORT not specified.'
                        }
                    }

            }       # END validate [SMTP] Port

            23 {    # BEGIN validate [SMTP] Server

                    if($Global:Ini.Alert.Method -match "^(?i)(.*)Smtp(.*)$"){

                        if($Global:Ini.Smtp.ContainsKey('Server') -eq $true){

                            if([System.String]::IsNullOrEmpty($Global:Ini.Smtp.Server) -eq $false){

                                try {

                                    $smtpServer = New-Object System.Net.Sockets.TcpClient($Global:Ini.Smtp.Server, $Global:Ini.Smtp.Port)

                                    if($smtpServer.Connected -eq $false){

                                        $ErrorMsg += '[Error][SMTP] TCP connection failed to {0}:{1}' -f $Global:Ini.Smtp.Server,$Global:Ini.Smtp.Port
                                    }

                                    $smtpServer.Dispose()

                                    Remove-Variable -Name smtpServer

                                } catch {

                                    $e = $_
                                    $ErrorMsg += '[Error][SMTP] TCP connection failed to {0}:{1}' -f $Global:Ini.Smtp.Server,$Global:Ini.Smtp.Port
                                    $ErrorMsg += $('[Error][SMTP] Exception: {0}' -f $e.Exception.Message)
                                }

                            } else {

                                $ErrorMsg += '[Error][SMTP] SERVER not specified.'
                            }

                        } else {

                            $ErrorMsg += '[Error][SMTP] SERVER not specified.'
                        }
                    }

            }       # END validate [SMTP] Server

            24 {    # BEGIN validate [SMTP] CredentialXml

                    if($Global:Ini.Alert.Method -match "^(?i)(.*)Smtp(.*)$"){

                        if($Global:Ini.Smtp.ContainsKey('CredentialXml') -eq $true){

                            if([System.String]::IsNullOrEmpty($Global:Ini.Smtp.CredentialXml) -eq $false){

                                try {

	                                $credFile = Get-Item -LiteralPath $Global:Ini.Smtp.CredentialXml -ErrorAction Stop

	                                $credCheck = Import-Clixml -LiteralPath $credFile.FullName

	                                if($credCheck.GetType().Name -ne 'PSCredential'){

		                                $ErrorMsg += '[Error][SMTP] CredentialXml import failed.'
	                                }

	                                Remove-Variable -Name credCheck,credFile

                                } catch {

                                    $ErrorMsg += '[Error][SMTP] CredentialXml import failed.'
                                }
                            }
                        }
                    }

            }       # END validate [SMTP] CredentialXml

            25 {    # BEGIN validate [WinEvent] Logname

                    if($Global:Ini.Alert.Method -match "^(?i)(.*)WinEvent(.*)$"){

                        if($Global:Ini.WinEvent.ContainsKey('Logname') -eq $true){

                            if([System.String]::IsNullOrEmpty($Global:Ini.WinEvent.Logname) -eq $false){

                                try {

                                    Get-WinEvent -LogName $Global:Ini.WinEvent.Logname -MaxEvents 1 -ErrorAction Stop | Out-Null

                                } catch {

                                    $ErrorMsg += '[Error][WinEvent] no Logname {0}' -f $Global:Ini.WinEvent.Logname
                                }

                            } else {

                                $ErrorMsg += '[Error][WinEvent] Logname not specified.'
                            }

                        } else {

                            $ErrorMsg += '[Error][WinEvent] Logname not specified.'
                        }
                    }

            }       # END validate [WinEvent] Logname

            26 {    # BEGIN validate [WinEvent] Source

                    if($Global:Ini.Alert.Method -match "^(?i)(.*)WinEvent(.*)$"){

                        if($Global:Ini.WinEvent.ContainsKey('Source') -eq $true){

                            if([System.String]::IsNullOrEmpty($Global:Ini.WinEvent.Source) -eq $false){

                                try{

                                    $result = [System.Diagnostics.EventLog]::SourceExists($Global:Ini.WinEvent.Source)

                                    if ($result -eq $false){

                                        $ErrorMsg += '[Error][WinEvent] Source does not exist.'
                                    }

                                } catch {

                                    $e = $_
                                    $ErrorMsg += '[Error][WinEvent] Source does not exist.'
                                    $ErrorMsg += '[Error][WinEvent] Exception: {0}' -f $e.Exception.Message
                                }

                            } else {

                                $ErrorMsg += '[Error][WinEvent] Source not specified.'
                            }

                        } else {

                            $ErrorMsg += '[Error][WinEvent] Source not specified.'
                        }
                    }

            }       # END validate [WinEvent] Source

            27 {    # BEGIN validate [WinEvent] InfoEventId

                    if($Global:Ini.Alert.Method -match "^(?i)(.*)WinEvent(.*)$"){

                        if($Global:Ini.WinEvent.ContainsKey('InfoEventId') -eq $true){

                            if([System.String]::IsNullOrEmpty($Global:Ini.WinEvent.InfoEventId) -eq $false){

                                [int]$intInfoEventId = 0

                                if([System.Int32]::TryParse($Global:Ini.WinEvent.InfoEventId, [ref]$intInfoEventId)){

                                    if($intInfoEventId -gt 0){

                                        [int]$Global:Ini.WinEvent.InfoEventId = $intInfoEventId

                                    } else {

                                        $ErrorMsg += '[Error][WinEvent] InfoEventId must be a positive number.'
                                    }

                                } else {

                                    $ErrorMsg += '[Error][WinEvent] InfoEventId must be a positive number.'
                                }

                            } else {

                                $ErrorMsg += '[Error][WinEvent] InfoEventId not specified.'
                            }

                        } else {

                            $ErrorMsg += '[Error][WinEvent] InfoEventId not specified.'
                        }
                    }

            }       # END validate [WinEvent] InfoEventId

            28 {    # BEGIN validate [WinEvent] ErrorEventId

                    if($Global:Ini.Alert.Method -match "^(?i)(.*)WinEvent(.*)$"){

                        if($Global:Ini.WinEvent.ContainsKey('ErrorEventId') -eq $true){

                            if([System.String]::IsNullOrEmpty($Global:Ini.WinEvent.ErrorEventId) -eq $false){

                                [int]$intErrorEventId = 0

                                if([System.Int32]::TryParse($Global:Ini.WinEvent.ErrorEventId, [ref]$intErrorEventId)){

                                    if($intErrorEventId -gt 0){

                                        [int]$Global:Ini.WinEvent.ErrorEventId = $intErrorEventId

                                    } else {

                                        $ErrorMsg += '[Error][WinEvent] ErrorEventId must be a positive number.'
                                    }

                                } else {

                                    $ErrorMsg += '[Error][WinEvent] ErrorEventId must be a positive number.'
                                }

                            } else {

                                $ErrorMsg += '[Error][WinEvent] ErrorEventId not specified.'
                            }

                        } else {

                            $ErrorMsg += '[Error][WinEvent] ErrorEventId not specified.'
                        }
                    }

            }       # END validate [WinEvent] ErrorEventId

            29 {    # BEGIN validate [WinEvent] InfoEventId and ErrorEventId different

                    if($Global:Ini.Alert.Method -match "^(?i)(.*)WinEvent(.*)$"){

                        if($Global:Ini.WinEvent.InfoEventId -eq $Global:Ini.WinEvent.ErrorEventId){

                            $ErrorMsg += '[Error][WinEvent] InfoEventId and ErrorEventId must different.'
                        }
                    }

            }       # END validate [WinEvent] InfoEventId and ErrorEventId different

            30 {    # BEGIN cleanup DnsBlockListCache files

                    $CacheFiles = Get-ChildItem -Path $Global:Ini.Script.WorkingDirectory | Where-Object{ $_.Extension -eq '.DnsBlockListCache' }

                    if($null -ne $CacheFiles){

                        foreach($file in $CacheFiles){

                            Write-Verbose -Message "CachedFile=$($file.FullName)"

                            if($Global:Ini.BlockListUrl.ContainsKey($file.BaseName) -eq $false){

                                Remove-Item -LiteralPath $file.FullName

                                Write-Verbose -Message "   Removed=$($file.FullName)"

                                if($Global:CacheConfig.ContainsKey($key) -eq $true){

                                    $Global:CacheConfig[$key].File = ''
                                    $Global:CacheConfig[$key].Url = ''
                                    $Global:CacheConfig[$key].etag = ''
                                    $Global:CacheConfig[$key].LastModified = ''
                                }
                            }
                        }
                    }

            }       # END cleanup DnsBlockListCache files

			default {

                if($Global:Ini['Script'].ContainsKey('HasError') -eq $false){

                    $Global:Ini['Script'].Add('HasError',$false)
                }

                if($ErrorMsg.Count -gt 0){

                    $Global:Ini['Script']['HasError'] = $true

                    $ErrorMsg = @('[Error][Script] Terminating error.') + $ErrorMsg

                    if($Global:Ini['Script'].ContainsKey('ErrorMsg') -eq $false){

                        $Global:Ini['Script'].Add('ErrorMsg',$ErrorMsg)

                    } else {

                        $Global:Ini['Script']['ErrorMsg'] = $ErrorMsg
                    }

                } else {

                    $Global:Ini['Script']['HasError'] = $false
                }

                $i = 0
            }
        }

    } while($i -gt 0)

	return $Global:Ini['Script']['HasError']

} # End Function Confirm-DnsBlockListSettings

Function Publish-QRPStats
{
    <#
    .SYNOPSIS

    Gets the QRP stats for alerts.

    .INPUTS

	System.Collections.Hashtable
    #>

    [CmdletBinding()]
    param(
            [parameter(Mandatory=$true)]
            [System.Collections.Hashtable]
            # Change object
            $Changes
	)

	[string[]]$StatMsg = @()
    [string[]]$AllQrpNames = @()
    [string[]]$DblQrp = @()

	[string[]]$AllQrpNames = Get-DnsServerQueryResolutionPolicy | ForEach-Object{ $_.Name }

    if($AllQrpNames.Count -gt 0){

        [string[]]$DblQrpRules = $AllQrpNames | Where-Object{ $_.StartsWith($Global:Ini.Script.RuleNamePrefix) }

        if($null -ne $DblQrpRules){

            if($DblQrpRules.Count -gt 0){

                [string[]]$DblQrp = $DblQrpRules
            }
        }
    }

	$StatMsg += 'QRP-Total = {0}' -f $AllQrpNames.Count
    $StatMsg += 'QRP-DnsBlockList = {0}' -f $DblQrp.count

	if($Changes.HasChanges -eq $true){

		$StatMsg += 'HasChanges = True'
		$StatMsg += 'Removed = {0}' -f $Changes.Remove.Count
		$StatMsg += 'Added = {0}' -f $Changes.Add.Count

	} else {

		$StatMsg += 'HasChanges = False'
		$StatMsg += 'Removed = 0'
		$StatMsg += 'Added = 0'
    }

	$StatMsg += 'ReadOnly = {0}' -f $Global:Ini.Script.ReadOnly
    $StatMsg += 'UpdateGit = {0}' -f $Global:Ini.Script.UpdateGit

	if($Global:Ini.Script.ContainsKey('Stats')){

		$Global:Ini.Script.Stats = $StatMsg

	} else {

		$Global:Ini.Script.Add('Stats',$StatMsg)
	}

} # End Function Publish-QRPStats

Function Get-DnsBlockListWebHeaders
{
    <#
    .SYNOPSIS

    Gets the HTTP request headers for the BlockListUrl.

	.DESCRIPTION

	Builds an HTTP request header hashset using Last-Modified and ETag values from the prior request so only updated content is downloaded.

    .INPUTS

	System.String

	.OUTPUTS

    System.Collections.Hashtable
    #>

    [CmdletBinding()]
    param(
			[parameter(Mandatory=$true)]
            [string]
            # Key used to specify the target DNS blocklist.
            $BlockListKey
	)

    $RequestHeaders = @{ 'User-Agent' = 'Mozilla/5.0 (Windows NT; Windows NT 10.0;)' }

    if($Global:CacheConfig.ContainsKey($BlockListKey) -eq $true){

        if([System.String]::IsNullOrEmpty($Global:CacheConfig[$BlockListKey]['LastModified']) -eq $false){

            $RequestHeaders.Add('If-Modified-Since',$Global:CacheConfig[$BlockListKey]['LastModified'])
        }

        if([System.String]::IsNullOrEmpty($Global:CacheConfig[$BlockListKey]['etag']) -eq $false){

            $RequestHeaders.Add('If-None-Match',$Global:CacheConfig[$BlockListKey]['etag'])
        }
    }

    return $RequestHeaders

} # End Function Get-DnsBlockListWebHeaders

Function Get-DnsBlockListWebFiles
{
    <#
    .SYNOPSIS

    Sends HTTP GET using custom headers to BlockListUrl.

	.DESCRIPTION

	Only downloads files that have changed by using Last-Modified timestamps and ETag values.

	.OUTPUTS

    System.Boolean
    #>

    [CmdletBinding()]
    param( )

    [string[]]$ErrorMsg = @()

	foreach($key in $Global:Ini.BlockListUrl.Keys){

        $SaveFilePath = Join-Path -Path $Global:Ini.Script.WorkingDirectory -ChildPath "$($key).DnsBlockListCache"

        $ClientRequestHeaders = Get-DnsBlockListWebHeaders -BlockList $key

		$Global:NewCache.Add($key,@{})
		$Global:NewCache[$key].Add('Url',$Global:Ini.BlockListUrl[$key])
		$Global:NewCache[$key].Add('etag','')
        $Global:NewCache[$key].Add('LastModified','')
        $Global:NewCache[$key].Add('File','')
		$Global:NewCache[$key].Add('ResponseCode','ERROR')

        try{

            $HttpResponse = Invoke-WebRequest -Uri $Global:Ini.BlockListUrl[$key] -Headers $ClientRequestHeaders -UseBasicParsing -ErrorAction Stop

			$Global:NewCache[$key]['ResponseCode'] = [int]$HttpResponse.StatusCode

            $Global:NewCache[$key]['File'] = $SaveFilePath

            Out-File -LiteralPath $Global:NewCache[$key]['File'] -InputObject $HttpResponse.Content -ErrorAction Stop

            Write-Verbose -Message "HTTP_Response=200 Key=$($key)"

            if($HttpResponse.Headers.ContainsKey('ETag')){

                if([System.String]::IsNullOrEmpty($HttpResponse.Headers['ETag']) -eq $false){

                    $Global:NewCache[$key]['etag'] = $HttpResponse.Headers['ETag']
                }
            }

            if($HttpResponse.Headers.ContainsKey('Last-Modified')){

                if([System.String]::IsNullOrEmpty($HttpResponse.Headers['Last-Modified']) -eq $false){

                    $Global:NewCache[$key]['LastModified'] = $HttpResponse.Headers['Last-Modified']
                }
            }

        } catch [System.Net.WebException] {

			$e = $_

            if($e.Exception.Message -match "^.*\([0-9]{3}\).*$"){

                $Global:NewCache[$key]['ResponseCode'] = [int]([regex]::Match($e.Exception.Message,'[0-9]{3}')).Value

                switch($Global:NewCache[$key]['ResponseCode']){

                    304 {   # (304) Not Modified.

                            Write-Verbose -Message "HTTP_Response=304 Key=$($key)"

                            $Global:NewCache[$key]['File'] = $SaveFilePath

                            if($ClientRequestHeaders.ContainsKey('If-Modified-Since')){

                                if([System.String]::IsNullOrEmpty($ClientRequestHeaders['If-Modified-Since']) -eq $false){

                                    $Global:NewCache[$key]['LastModified'] = $ClientRequestHeaders['If-Modified-Since']
                                }
                            }

                            if($ClientRequestHeaders.ContainsKey('If-None-Match')){

                                if([System.String]::IsNullOrEmpty($ClientRequestHeaders['If-None-Match']) -eq $false){

                                    $Global:NewCache[$key]['etag'] = $ClientRequestHeaders['If-None-Match']
                                }
                            }

                    }       # (304) Not Modified.

                    default {

                            $ErrorMsg += $('[Error][Http] Processing: {0} = {1}' -f $key,$Global:Ini.BlockListUrl[$key])
                            $ErrorMsg += $('[Error][Http] Exception: {0}' -f $e.Exception.Message)
                    }
                }

            } else {

                $ErrorMsg += $('[Error][Http] Processing: {0} = {1}' -f $key,$Global:Ini.BlockListUrl[$key])
                $ErrorMsg += $('[Error][Http] Exception: {0}' -f $e.Exception.Message)
            }

        } catch {

            $e = $_
            $ErrorMsg += $('[Error][Http] Processing: {0} = {1}' -f $key,$Global:Ini.BlockListUrl[$key])
            $ErrorMsg += $('[Error][Http] Exception: {0}' -f $e.Exception.Message)
        }
    }

    return $ErrorMsg

} # End Function Get-DnsBlockListWebFiles

Function Set-ReadMeAndIniPath
{
    <#
    .SYNOPSIS

    Set path for README and default configuration file in global variables.
    #>

    [CmdletBinding()]
    param( )

	if([System.String]::IsNullOrEmpty($Global:Ini['Script'])){

		$Global:Ini.Add('Script',@{})
	}

	$ReadMePath = Join-Path -Path $PSScriptRoot -ChildPath 'README.md'

	$Global:DBLReadme = $ReadMePath

	$DefaultConfigPath = Join-Path -Path $PSScriptRoot -ChildPath 'DnsBlockList.ini'

	$Global:DBLDefaultConfig = $DefaultConfigPath

} # End Function Set-ReadMeAndIniPath

Function Get-DnsBlockListREADME
{
    <#
    .SYNOPSIS

    Returns the DnsBlockList README file (README.md) to standard out.
    #>

    [CmdletBinding()]
    param( )

	try {

		$ReadMeFile = Get-Item -LiteralPath $Global:DBLReadme -ErrorAction Stop

		Get-Content -LiteralPath $ReadMeFile.FullName | ForEach-Object{ Write-Output $_ }

	} catch {

		$e = $_
		Write-Output $('[Error][Script] Exception: {0}' -f $e.Exception.Message)
	}

} # End Function Get-DnsBlockListREADME

Function Copy-DnsBlockListREADME
{
    <#
    .SYNOPSIS

    Copies the DnsBlockList README file (README.md) to the destination folder.
    #>

    [CmdletBinding()]
    param(
			[parameter(Mandatory=$true)]
            [ValidateScript({Test-Path -LiteralPath $_ -PathType Container})]
			[string]
            # Destination folder to copy README.md
            $DestinationFolder
	)

	try {

		$ReadMeFile = Get-Item -LiteralPath $Global:DBLReadme -ErrorAction Stop

		Copy-Item -Path $ReadMeFile.FullName -Destination $DestinationFolder

	} catch {

		$e = $_
		Write-Output $('[Error][Script] Exception: {0}' -f $e.Exception.Message)
	}

} # End Function Copy-DnsBlockListReadme

Function Get-DnsBlockListDefaultConfiguration
{
    <#
    .SYNOPSIS

    Returns the DnsBlockList default configuration file to standard out.
    #>

    [CmdletBinding()]
    param( )

	try {

		$ConfigFile = Get-Item -LiteralPath $Global:DBLDefaultConfig -ErrorAction Stop

		Get-Content -LiteralPath $ConfigFile.FullName | ForEach-Object{ Write-Output $_ }

	} catch {

		$e = $_
		Write-Output $('[Error][Script] Exception: {0}' -f $e.Exception.Message)
	}

} # End Function Get-DnsBlockListDefaultConfiguration

Function Copy-DnsBlockListDefaultConfiguration
{
    <#
    .SYNOPSIS

    Copies the DnsBlockList default configuration file to the destination folder.
    #>

    [CmdletBinding()]
    param(
			[parameter(Mandatory=$true)]
			[ValidateScript({Test-Path -LiteralPath $_ -PathType Container})]
            [string]
            # Destination folder to copy DnsBlockList.ini
            $DestinationFolder
	)

	try {

		$ConfigFile = Get-Item -LiteralPath $Global:DBLDefaultConfig -ErrorAction Stop

		Copy-Item -Path $ConfigFile.FullName -Destination $DestinationFolder

	} catch {

		$e = $_
		Write-Output $('[Error][Script] Exception: {0}' -f $e.Exception.Message)
	}

} # End Function Copy-DnsBlockListDefaultConfiguration

Function Get-DomainFromLine
{
	<#
    .SYNOPSIS

    Extracts the domain name from the provided line of text.

	.DESCRIPTION

	This function will parse the provided line of text according to the ParseMethod defined in the configuration file.

	When a file needs an alternate parsing method, add the appropriate logic to the switch statement in this function. Then update the configuration file ParseMethod to reflect the switch value.

	.OUTPUTS

    System.String
    #>

    [CmdletBinding()]
    param(
		[parameter(Mandatory=$true)]
        [int]
        # ParseMethod value for DnsBlockList
        $ParseMethod
		,
		[parameter(Mandatory=$true)]
        [string]
        # Line of text to parse.
		$ParseLine
	)

	switch ($ParseMethod) {

		1 { # malwaredomains

			return ($ParseLine.Trim().Split("`t")[0]).Trim().ToLower()
		}

		Default { # Default Parse is one domain per line

			return $ParseLine.Trim().ToLower()
		}
	}

} # End Function Get-DomainFromLine

Set-ReadMeAndIniPath
