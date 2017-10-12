# Certificate scanner

Scan tool for finding and reporting installed SSL certificates.

## Overview

 - Queries DNS server zones to find fully qualified domain names
 - Scans each domain name on known SSL ports (supports split DNS and server name indication)
 - Found certificates are added/updated to sql-table
 - Reports expiring certificates found last 24h by sending SNMP traps (v2)
 
## Getting Started

 - If all prerequisites are met and you just want to run the scanner, download from [Releases](https://github.com/LarsHolte/CertificateScanner/releases/latest) and edit the .Config settings to suit your environment
 - .Config key explanation
   - "DNSServerZone##" : specifies which "<DNS Server IP>;<DNS Zone>" should be queried, add/remove lines as needed
   - "Ports" : domain names found will be attempted contacted on these ports
   - "SNMPServer" : the SNMP server IP where traps will be sent
   - "SQLConnectionString" : connection string for connecting to the SQL database
   - "MaxErrorDaysThreshold" : If the scanner is unable to complete a full scan within this period it will send a Critical SNMP trap 
   - "MaxDaysThresholdWarning" : Any certificates within this expire threshold will trigger sending a Warning SNMP trap
   - "MaxDaysThresholdCritical" : Any certificates within this expire threshold will trigger sending a Critical SNMP trap
 - The scanner is pre-configured to only report on certificates found the last 24 hours
 - All certificates within the expire period will be sent in the same trap message overwriting existing status where Critical > Warning > Normal
 
## Prerequisites (host running the Certificate scanner)

 - .NETFramework v4.5.2 minimum
 - Zone transfer permissions on the DNS server zones being queried
 - Configured scan ports open in firewall to hosts being scanned
 - Access to a Microsoft SQL server database
   - Add a table with the included makeTable.sql script
 - Access to a SNMP trap server, see SNMP Resources for SNMP setup
 
## Dependencies for building

 - NuGet packages
   - Lextm.SharpSnmpLib (https://docs.sharpsnmp.com)
   - ARSoft.Tools.Net (https://github.com/alexreinert/ARSoft.Tools.Net)
	 - BouncyCastle.Crypto (http://www.bouncycastle.org/csharp/) (required by ARSoft.Tools.Net)

## SNMP Resources

 - Any SNMP trap capable server should be supported. It has been testet on a [Nagiox XI](https://www.nagios.com/products/nagios-xi/) installation.
	- snmptt.conf - Nagios XI configuration file containing the fake OID translation rules
 - Nagios SNMP guides
    - [How to Integrate SNMP Traps With Nagios XI](https://assets.nagios.com/downloads/nagiosxi/docs/Integrating_SNMP_Traps_With_Nagios_XI.pdf) (pdf)
	- [SNMP Trap - snmptt Service](https://support.nagios.com/kb/article.php?id=89)
	- [SNMP Traps - Understanding Trap Variables](https://support.nagios.com/kb/article/snmp-traps-understanding-trap-variables.html)
	- [Nagios XI - SNMP Trap Tutorial](https://support.nagios.com/kb/article/nagios-xi-snmp-trap-tutorial.html)
	
## Known issues

 - Zone transfers fails on zones with large number of records (usually above ~5000 answers)
	
## Improvement proposals
 
 - Switch to using LiteDB instead of MSSql for easier setup/portability
 - Add support for sending e-mail when thresholds are hit
 - Make a valid OID and MIB
 - Make scanning multi-threaded to speed up the process

# License

This project is licensed under the MIT License

# Acknowledgments

 - [Lex Li](https://github.com/lextm) - Sharp SNMP Library
 - [Alexreinert](https://github.com/alexreinert) - C# DNS client/server and SPF Library 
 - [The Legion of the Bouncy Castle](http://www.bouncycastle.org/index.html) - Bouncy Castle Crypto APIs 

