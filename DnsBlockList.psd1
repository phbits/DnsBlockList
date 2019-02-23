@{

# Script module or binary module file associated with this manifest.
RootModule = 'DnsBlockList.psm1'

# Version number of this module.
ModuleVersion = '1.0.0.0'

# ID used to uniquely identify this module
GUID = '114cca09-6d28-4198-8692-7d3efefd1b0d'

# Author of this module
Author = 'phbits'

# Company or vendor of this module
CompanyName = 'phbits'

# Copyright statement for this module
Copyright = '(c) 2019 phbits. All rights reserved.'

# Description of the functionality provided by this module
Description = 'This PowerShell module was created to automate the aggregation of DNS blocklists for the creation of Query Resolution Policies (QRP) on a Microsoft DNS server.'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '5.0'

# Modules that must be imported into the global environment prior to importing this module
RequiredModules = 'DnsServer'

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = 'Invoke-DnsBlockList',
					'Clear-DnsBlockListQRP',
					'Clear-DnsBlockListQRPManually',
					'Get-DnsBlockListREADME',
					'Copy-DnsBlockListREADME',
					'Get-DnsBlockListDefaultConfiguration',
					'Copy-DnsBlockListDefaultConfiguration'

# Variables to export from this module
VariablesToExport = '*'

# List of all files packaged with this module
FileList = 'README.md','DnsBlockList.ini'

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        Tags = 'DNS','Domain','Block','Security','QRP'

        # A URL to the main website for this project.
        ProjectUri = 'https://github.com/phbits/DnsBlockList'

        # ReleaseNotes of this module
        ReleaseNotes = 'Tested on Windows Server 2016'

    } # End of PSData hashtable

} # End of PrivateData hashtable

}
