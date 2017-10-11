Certificate scanner

# Overview

 - Queries DNS server zones to find fully qualified domain names
 - Scans each domain name on known SSL ports (supports split DNS and server name indication)
 - Found certificates are added/updated to sql-table
 - Reports expiring certificates found last 24h by sending SNMP traps (v2)

# .Config key explanation

 - "DNSServerZone##" : includes which "<DNS Server IP>;<DNS Zone>" should be queried
 - "Ports" : hostnames found will attempted contacted on these ports
 - "SNMPServer" : the SNMP server where traps will be sent
 - "SQLConnectionString" : connection string for connecting to the SQL database
 - "MaxErrorDaysThreshold" : If the scanner is unable to complete a full scan within this period it will send a Critical SNMP trap 
 - "MaxDaysThresholdWarning" : Any certificates within this threshold will trigger sending a Warning SNMP trap
 - "MaxDaysThresholdCritical" : Any certificates within this threshold will trigger sending a Critical SNMP trap

# Requirements (host running the Certificate scanner)

 - .NETFramework v4.5.2 minimum
 - Zone transfer permissions on the DNS server zones being queried
 - Configured scan ports open in firewall to hosts being scanned
 - Access to a Microsoft SQL server
 - Access to a SNMP trap server
 
# Dependencies

 - Lextm.SharpSnmpLib (https://docs.sharpsnmp.com)
 - ARSoft.Tools.Net (https://github.com/alexreinert/ARSoft.Tools.Net)
	- BouncyCastle.Crypto (http://www.bouncycastle.org/csharp/)

# Resources

 - Extra files included in project
	- snmptt.conf - Nagios XI configuration file containing the fake OID translation rules
	- makeTable.sql - Sql script for creating a table in an existing database for storing found certificates 
 - Nagios SNMP guides
    - How to Integrate SNMP Traps With Nagios XI - https://assets.nagios.com/downloads/nagiosxi/docs/Integrating_SNMP_Traps_With_Nagios_XI.pdf
	- SNMP Trap - snmptt Service - https://support.nagios.com/kb/article.php?id=89
	- SNMP Traps - Understanding Trap Variables - https://support.nagios.com/kb/article/snmp-traps-understanding-trap-variables.html
	- Nagios XI - SNMP Trap Tutorial - https://support.nagios.com/kb/article/nagios-xi-snmp-trap-tutorial.html
	
# Known issues

 - Zone transfers fails on zones with large number of records (usually above ~5000 answers)
	
# Improvement proposals
 
 - Switch to dumping DNS zones with "nslookup ls" as a workaround instead of ARSoft.Tools.Net
 - Switch to using LiteDB instead of MSSql for easier setup/portability
 - Add support for sending e-mail when thresholds are hit
 - Make a valid OID and MIB



	


