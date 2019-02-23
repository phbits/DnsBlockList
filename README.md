
# DnsBlockList #

This PowerShell module was created to automate the aggregation of DNS blocklists for the creation of Query Resolution Policies (QRP) on a Microsoft DNS server.



# Overview #

The DnsBlockList module first reads and validates the provided configuration file. Then the Query Resolution Policies (QRP) are processed to get domains currently loaded. Next, each `BlockListUrl` is queried for changes and updated files are downloaded to the `WorkingDirectory` as a `.DnsBlockListCache` file. All files are processed and the aggregated list of domains get compared with those currently loaded to produce the add/remove commands in `Update-DnsServerQRP.ps1`.

###### More Information ######

[Microsoft DNS Policies Overview](https://docs.microsoft.com/en-us/windows-server/networking/dns/deploy/dns-policies-overview)



# Prerequisites #

The following are prerequisites for this module.


## TLS 1.2 ##

This module is hard coded to use TLS 1.2 for all secure communications which impacts the following:

- HTTPS communications to a blocklist URL.
- Secure communication to the SMTP server (e.g. STARTTLS) if using SMTP for alerts.


## DNS Server ##

This module must run on a DNS server since it queries the Query Resolution Policies (QRP) currently in use.


## Permissions ##

The user account running this script must be a DNS server administrator.



# Scheduling #

This module should be launched via Task Scheduler on a reoccurring schedule that works best for your environment.



# Configuration File Settings #

The DnsBlockList module uses a configuration file. Each setting is described in detail below. 

There are two functions in this module used for working with the default configuration file.

- `Get-DnsBlockListDefaultConfiguration` - returns the content of the default configuration file to standard out.
- `Copy-DnsBlockListDefaultConfiguration` - copies the default configuration file to the destination folder.


## [Script] WorkingDirectory ##

Directory for storing the following files:

- `CacheConfig.xml` - Stores HTTP response headers ETag and/or Last-Modified timestamp for DnsBlockList files.
- `Update-DnsServerQRP.ps1` - File containing PowerShell QRP Add/Remove commands.
- `*.DnsBlockListCache` - DnsBlockList files are stored using this extension with it's `Key` as the name.

Example of naming a downloaded file:

```configuration
SansHigh = https://isc.sans.edu/feeds/suspiciousdomains_High.txt
Cached Filename = SansHigh.DnsBlockListCache
```


## [Script] DnsResponse ##

Action when a Query Resolution Policy is matched:

- `Allow`
- `Deny` Respond with SERV_FAIL.
- `Ignore` Do not respond.

###### More Information ######

[https://docs.microsoft.com/en-us/powershell/module/dnsserver/add-dnsserverqueryresolutionpolicy#optional-parameters](https://docs.microsoft.com/en-us/powershell/module/dnsserver/add-dnsserverqueryresolutionpolicy#optional-parameters)


## [Script] RuleNamePrefix ##

Unique prefix to distinguished DnsBlockList rules from all other QRP rules.

Example of how a QRP name is created:

```configuration
RuleNamePrefix = DBL-
Blocked Domain = bad.contoso.com
Resulting QRP Name = DBL-bad.contoso.com
```


## [Script] ReadOnly ##

Specifies whether the module will add/remove QRPs.

- `False` - add/remove domains as they're processed.
- `True` - no changes are made to QRPs via this script.

> `Update-DnsServerQRP.ps1` is updated with change commands regardless of this setting.


## [Script] UpdateGit ##

If the `WorkingDirectory` has been setup for git, enabling this setting will commit and push any changes.

- `False` - Does not run the git commands.
- `True` - The following git commands will be launched in the working directory.

```
git add -A
git commit -m "DnsBlockList-PowerShell-Module"
git push origin master
```


## [BlockListUrl] ##

Each blocklist must be listed as a `key=value` pair where:

- `Key` = Unique identifier for the blocklist.
- `Value` = blocklist URL

###### Example ######

```configuration
[BlockListUrl]
SansHigh = https://isc.sans.edu/feeds/suspiciousdomains_High.txt
ZeusTracker = https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist
MalwareDomains = https://mirror1.malwaredomains.com/files/domains.txt
```


> NOTE: this script is hard-coded to use `TLS1.2` when communicating with web servers.

###### Additional Resources ######

[SANS - Suspicious Domains](https://isc.sans.edu/suspicious_domains.html)

[LENNY ZELTSER - Blocklists of Suspected Malicious IPs and URLs](https://zeltser.com/malicious-ip-blocklists/)


## [AllowDomains] ##

Domains that should never be block must be listed here as a `key=value` pair where:

- `Key` = Unique identifier for the allowed domain.
- `Value` = domain name

###### Example ######

```configuration
[AllowDomains]
CompanyEmail = mail.domain.com
CompanyWebsite = www.domain.com
```


## [BlockDomains] ##

Individual domains to be blocked must be listed here as a `key=value` pair where:

- `Key` = Unique identifier for the blocked domain.
- `Value` = domain name

###### Example ######

```configuration
[BlockDomains]
PhishingEmail01 = foo.evil.com
```

***NOTE***: if your implementation requires frequent edits to this section consider hosting a `BlockListUrl` internally.


## [ParseMethod] ##

Not all blocklists are structured as having one domain per line. For those occasions additional parsing logic is needed which is handled by the private function `Get-DomainFromLine`. For a line to be handed off to this function, it must meet the following criteria:

1. Cannot start with a `#` (hash sign)
2. Must contain a `.` (period)
3. Length > 2

If there's a BlockList requiring an additional parse method and the line meets the above requirements, do the following:

1. Add the appropriate parsing logic to the switch statement in the `Get-DomainFromLine` private function.
2. Update this configuration section with the `Key` of the `BlockListUrl` and the `Value` newly added to the switch statement.


###### Example ######

MalwareDomains requires alternate parsing and thus uses the following configuration. Note how the same `Key` is used to associate the `ParseMethod` with the `BlockListUrl`.
    
```configuration
[BlockListUrl]
MalwareDomains = https://mirror1.malwaredomains.com/files/domains.txt
[ParseMethod]
MalwareDomains = 1
```


## [Alert] Method ##

Standard out will always be used even if no value is specified. Choosing both Smtp and WinEvent will enable both methods or just include one.

- Standard Out - Always enabled. Will return any alerts to the prompt.
- Smtp - Send an email based on the `[SMTP]` settings.
- WinEvent - Write an event based on the `[WinEvent]` settings.


## [Smtp] To ##

Recipient email address for the alert.


## [Smtp] From ##

Sender's email address for the alert.


## [Smtp] Subject ##

Email subject for the alert.


## [Smtp] Server ##

DNS name of SMTP server.

> NOTE: this script is hard-coded to use `TLS1.2` when communicating with this server.


## [Smtp] Port ##

SMTP server port to connect to.


## [Smtp] CredentialXml ##

Optional setting. XML file containing PSCredential for SMTP authentication. Leave blank if no credentials are to be used.

To create this file run the following command using the account that will be launching this module.


```powershell
Get-Credential | Export-Clixml -Path <CredentialXmlPath>
```


Ensure NTFS permissions on the PSCredential xml file are tuned to only allow access to SYSTEM, any backup accounts, and the user running this module.


## [WinEvent] LogName ##

The target event log to write an event to.


## [WinEvent] Source ##

Name of the application that generated this event. 

By default, `DnsBlockList` will not be registered. Doing so requires Administrative permission and can be achieved via the following command.


```powershell
New-EventLog -LogName Application -Source DnsBlockList
```


## [WinEvent] InfoEventId ##

Event Id used when writing an Information event.


## [WinEvent] ErrorEventId ##

Event Id used when writing an Error event.
