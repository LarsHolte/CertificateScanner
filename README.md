# Certificate scanner

Brute force scan tool for finding and reporting installed SSL certificates.

## Overview

 - Queries DNS server zones to find fully qualified domain names (supports servers capable of zone transfers and AzureDNS)
 - Scans each domain name on configurable ports (supports split DNS and server name indication)
 - Found certificates are added/updated to sql-table
 - Send mail/trap notifications if enabled for certificates detected last 24h
 
## Getting Started

 - If all prerequisites are met and you just want to run the scanner, download from [Releases](https://github.com/LarsHolte/CertificateScanner/releases/latest)
 - Find/make a database and run makeTable.sql to create the table needed for storing found certificates  
 - Rename App.config.default to App.config and update it to your environment
 - Create a task in task scheduler to run the exe every 24h
 
## Prerequisites

 - Host server running the CertificateScanner
   - .NETFramework v4.5.2 minimum
   - Zone transfer permissions on the DNS server zones being queried
   - Access to a Microsoft SQL server database
   - Access to a SNMP server for sending traps if trap notification is enabled, see SNMP Resources for SNMP setup 
   - Access to a SMTP server for sending mail if mail notification is enabled
 - If querying AzureDNS a service principal with Reader access to the resource groups [must be created](https://docs.microsoft.com/en-us/powershell/azure/create-azure-service-principal-azureps)
 
## SNMP Resources

 - Any SNMP trap capable server should be supported. It has been testet on a [Nagiox XI](https://www.nagios.com/products/nagios-xi/) installation.
	- snmptt.conf - Nagios XI configuration file containing the fake OID translation rules
 - Nagios SNMP guides
    - [How to Integrate SNMP Traps With Nagios XI](https://assets.nagios.com/downloads/nagiosxi/docs/Integrating_SNMP_Traps_With_Nagios_XI.pdf) (pdf)
	- [SNMP Trap - snmptt Service](https://support.nagios.com/kb/article.php?id=89)
	- [SNMP Traps - Understanding Trap Variables](https://support.nagios.com/kb/article/snmp-traps-understanding-trap-variables.html)
	- [Nagios XI - SNMP Trap Tutorial](https://support.nagios.com/kb/article/nagios-xi-snmp-trap-tutorial.html)
	
## Improvement proposals
 
 - Switch to using LiteDB instead of MSSql for easier setup/portability

## License

This project is licensed under the [MIT License](https://github.com/LarsHolte/CertificateScanner/blob/master/LICENSE)

## Acknowledgments

 - [Lex Li](https://github.com/lextm) - Sharp SNMP Library

## Changelog

 - 2.0.0.0
  - Added support for AzureDNS
  - Added multithreading to speed up scanning (from ~1 port per 5 second to ~11 ports per second)
  - Added support for sending mail notifications
  - Removed ARSoft.Tools.Net (large zone transfer issue) and BouncyCastle dependency
  - Added using nslookup for zone transfers
  - Added configurable regex filtering to exclude DNS records from scan
  - Added configurable loglevel
 - 1.0.0.1
  - Added configurable timeout value "HttpWebRequestTimeout".
  - Increased default DNS AXFR transfer timeout to 5 minutes to resolve large (20k+) zone queries timing out.
  - Added sql column "ignore" (bit) to flag certificates we do not want snmp traps for (eg. self signed or test scenarios).
  - Bugfix: servers with the same certificate installed on different ports was updating previously found, instead of adding new.
 - 1.0.0.0 
  - Initial release
