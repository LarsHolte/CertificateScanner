# Certificate scanner

Brute force scan tool for finding and reporting installed SSL certificates based on A and CNAME records found in DNS zones.

## Overview

 - Queries DNS server zones to find fully qualified domain names (supports servers capable of zone transfers and AzureDNS)
 - Scans each domain name on configurable ports (supports split DNS and server name indication)
 - Found certificates are added/updated to sql-table
 - Send mail/trap notifications if enabled for certificates detected last 24h
 
## Getting Started

 - If all prerequisites are met and you just want to run the scanner, download from [Releases](https://github.com/LarsHolte/CertificateScanner/releases/latest)
 - Find/make a database and run makeTable.sql to create the table needed for storing found certificates  
 - Update CertificateScanner.dll.config to your environment
 - Create a task in task scheduler to run the exe every 24h
 
## Prerequisites

 - Windows x64 OS with:
   - [.NET Runtime 6.0 (Windows x64)](https://dotnet.microsoft.com/en-us/download/dotnet/6.0) 
   - Zone transfer permissions on the DNS server zones being queried
   - Access to a Microsoft SQL server database
   - Access to a SNMP server for sending traps if trap notification is enabled, see SNMP Resources for SNMP setup
       - Traps sent are (OID/Severity): .2.25.999.1/Normal | .2.25.999.2/Warning | .2.25.999.3/Critical
   - Access to a SMTP server for sending mail if mail notification is enabled
 - If querying AzureDNS, a service principal with Reader access to the resource groups [must be created](https://docs.microsoft.com/en-us/powershell/azure/create-azure-service-principal-azureps)

## SNMP Resources

 - Any SNMP trap capable server should be supported. It has been testet on a [Nagiox XI](https://www.nagios.com/products/nagios-xi/) installation.
    - [How to Integrate SNMP Traps With Nagios XI](https://assets.nagios.com/downloads/nagiosxi/docs/Integrating_SNMP_Traps_With_Nagios_XI.pdf) (pdf)
    - [Using the SNMP trap interface in Nagios XI](https://www.youtube.com/watch?v=0lhFHtdl8UE) (youttube)
    
## License

This project is licensed under the [MIT License](https://github.com/LarsHolte/CertificateScanner/blob/master/LICENSE)

## Acknowledgments

 - [Lex Li](https://github.com/lextm) - Sharp SNMP Library

## Changelog

- 3.0.0.0 - 2023-09-06
  - Updated from .NET Framework 4.7.2 to .NET 6.0
  - Reverted scanning for FQDN certificates first (breaks split DNS scenarios)
  - Updated and replaced deprecated dependencies with Azure.Identity and Azure.ResourceManager.Dns
- 2.1.1.0 - 2023-09-03
  - Updated to use certificates found by SNI first (webservers with mixed SNI sites on/off would only find the ip certificate)
  - Added configurable sql table name
  - Added more logging
  - Bugfix: logLevel still not properly initialized
- 2.1.0.0 - 2021-09-15
  - Updated to .NET Framework 4.7.2
  - Updated to use HttpClient instead of HttpWebRequest
  - Added configurable concurrent webrequests "ConcurrentWebRequests" to throttle tasks
  - Added support to get the custom domain certificate from Azure App service and Azure Application proxy
  - Added more logging and known exceptions handling
  - Bugfix: subjectAlternativeNames not updating
  - Bugfix: servers with the same certificate installed on different ports was updating both
  - Bugfix: logLevel not properly initialized
  - Bugfix: also set lastScannedDate on newly detected certificates
- 2.0.0.0 - 2021-06-28
  - Added support for AzureDNS
  - Added multithreading to speed up scanning (from ~1 port per 5 second to ~11 ports per second)
  - Added support for sending mail notifications
  - Removed ARSoft.Tools.Net (large zone transfer issue) and BouncyCastle dependency
  - Added using nslookup for zone transfers
  - Added configurable regex filtering to exclude DNS records from scan
  - Added configurable loglevel
- 1.0.0.1 - 2018-11-26
  - Added configurable timeout value "HttpWebRequestTimeout"
  - Increased default DNS AXFR transfer timeout to 5 minutes to resolve large (20k+) zone queries timing out
  - Added sql column "ignore" (bit) to flag certificates we do not want snmp traps for (eg. self signed or test scenarios)
  - Bugfix: servers with the same certificate installed on different ports was updating previously found, instead of adding new
- 1.0.0.0 - 2017-10-12
  - Initial release