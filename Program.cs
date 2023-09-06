using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Diagnostics;
using System.Text.RegularExpressions;
using System.Net.Mail;
using System.Configuration;
using System.Data;
using System.Data.SqlClient;
using Azure.Core;
using Azure.Identity;
using Azure.ResourceManager;
using Azure.ResourceManager.Dns;
using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Messaging;

namespace CertificateScanner
{
    public class Globals
    {
        public static FileInfo appStartPath = new(new Uri(Assembly.GetExecutingAssembly().Location).LocalPath);
        public static string logLastRunFile = appStartPath.DirectoryName + @"\LogLastRun.txt";
        public static string logFile = appStartPath.DirectoryName + @"\logs\DATE.txt";
        public static bool hasErrorsCompleting = false;

        // Read from App.config
        public static string tenantId;
        public static string clientId;
        public static string secret;
        public static List<string> portsToScan;
        public static List<string> filters = new();
        public static string sendEmailNotification;
        public static string smtpServer;
        public static string smtpUsername;
        public static string smtpPassword;
        public static string smtpFromAddress;
        public static string smtpToAddresses;
        public static string sendTrapNotification;
        public static string sqlConnectionString;
        public static string certificatesLogTable;
        public static int concurrentWebRequests;
        public static TimeSpan httpClientTimeout;
        
        // DataTable to store DNS records found in the different zones
        public static DataTable dtDNSrecs = new();
    }

    class Program
    {
        [DllImport("dnsapi.dll", EntryPoint = "DnsFlushResolverCache")]
        private static extern UInt32 DnsFlushResolverCache();

        public static void FlushDNSCache()
        {
            _ = DnsFlushResolverCache();
        }
        public enum LogLevel { Trace = 0, Debug = 1, Information = 2, Warning = 3, Error = 4, Critical = 5, None = 6 }
        public static LogLevel logLevel = new();
        public enum TrapStatus { Normal = 1, Warning = 2, Critical = 3 }

        static async Task Main()
        {
            Globals.dtDNSrecs.Columns.Add("hostnameFQDN");
            Globals.dtDNSrecs.Columns.Add("endpoint");
            Globals.dtDNSrecs.Columns.Add("dnsServerIP");
            Globals.dtDNSrecs.Columns.Add("dnsZone");

            Directory.CreateDirectory(Globals.appStartPath.DirectoryName + @"\logs");

            #region ### CONFIGURATION ###
            string snmpServer = string.Empty;
            List<string> azureDnsServerZones = new();
            List<string> dnsServerZones = new();
            int maxErrorDaysThreshold = 0;
            int maxDaysThresholdWarning = 0;
            int maxDaysThresholdCritical = 0;
            try
            {
                Configuration configManager = ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None);
                KeyValueConfigurationCollection confCollection = configManager.AppSettings.Settings;
                Globals.tenantId = ConfigurationManager.AppSettings["TenantId"];
                Globals.clientId = ConfigurationManager.AppSettings["ClientId"];
                Globals.secret = ConfigurationManager.AppSettings["Secret"];
                Globals.portsToScan = ConfigurationManager.AppSettings["Ports"].Split(',').ToList();
                Globals.sendEmailNotification = ConfigurationManager.AppSettings["SendEmailNotification"];
                Globals.smtpServer = ConfigurationManager.AppSettings["SMTPServer"];
                Globals.smtpUsername = ConfigurationManager.AppSettings["SMTPUsername"];
                Globals.smtpPassword = ConfigurationManager.AppSettings["SMTPPassword"];
                Globals.smtpFromAddress = ConfigurationManager.AppSettings["SMTPFromAddress"];
                Globals.smtpToAddresses = ConfigurationManager.AppSettings["SMTPToAddresses"];
                Globals.sendTrapNotification = ConfigurationManager.AppSettings["SendTrapNotification"];
                snmpServer = ConfigurationManager.AppSettings["SNMPServer"];
                Globals.sqlConnectionString = ConfigurationManager.AppSettings["SQLConnectionString"];
                Globals.certificatesLogTable = ConfigurationManager.AppSettings["SQLTable"];
                maxErrorDaysThreshold = int.Parse(ConfigurationManager.AppSettings["MaxErrorDaysThreshold"]);
                maxDaysThresholdWarning = int.Parse(ConfigurationManager.AppSettings["MaxDaysThresholdWarning"]);
                maxDaysThresholdCritical = int.Parse(ConfigurationManager.AppSettings["MaxDaysThresholdCritical"]);
                Globals.concurrentWebRequests = int.Parse(ConfigurationManager.AppSettings["ConcurrentWebRequests"]);
                Globals.httpClientTimeout = TimeSpan.FromMilliseconds(int.Parse(ConfigurationManager.AppSettings["HttpClientTimeout"]));
                _ = Enum.TryParse(ConfigurationManager.AppSettings["LogLevel"], out logLevel);
                foreach (string key in ConfigurationManager.AppSettings)
                {
                    if (key.ToLower().StartsWith("dnsserverzone"))
                        dnsServerZones.Add(ConfigurationManager.AppSettings[key]);
                    if (key.ToLower().StartsWith("regexfilter"))
                        Globals.filters.Add(ConfigurationManager.AppSettings[key]);
                }
                WriteLog("INF: LogLevel=" + logLevel.ToString());
            }
            catch (Exception ex)
            {
                WriteLog("ERR: Failed to read configuration Exception: " + ex.ToString());
            }
            #endregion

            #region ### LAST RUN CHECK ###
            // Last run check, send trap if we have been unable to complete a certificate scan for X days
            DateTime lastRun = new();
            if (File.Exists(Globals.logLastRunFile))
            {
                lastRun = DateTime.Parse(File.ReadAllText(Globals.logLastRunFile));
                if (lastRun.AddDays(maxErrorDaysThreshold) < DateTime.Now)
                {
                    if (Globals.sendTrapNotification == "1")
                    {
                        SendTrap(snmpServer, TrapStatus.Critical, "Certificate scanner has not completed a certificate scan for over " + maxErrorDaysThreshold.ToString() + " days, check error logs!");
                    }
                    if (Globals.sendEmailNotification == "1")
                    {
                        string mailBody = "CertificateScanner has been unable to complete a scan in " + maxErrorDaysThreshold.ToString() + " days. If the scanner is scheduled to run less frequent than the value of MaxErrorDaysThreshold in App.config, consider raising that value, or run the scanner more frequently.";
                        SendEmail(Globals.smtpFromAddress, Globals.smtpToAddresses, "CertificateScanner failed for " + maxErrorDaysThreshold.ToString() + " days", mailBody, false);
                    }
                    Globals.hasErrorsCompleting = true; // Set so we dont overwrite snmp status unless we are able to successfully complete
                }
            }
            else
                File.WriteAllText(Globals.logLastRunFile, DateTime.Now.ToString()); // Create initial log file
            #endregion
            
            #region ### WORK - GET DNS RECORDS AND SCAN ###
            foreach (string dnsServerZone in dnsServerZones)
            {
                FlushDNSCache();
                string dnsServerIP = String.Empty;
                string dnsZone = String.Empty;
                int recordsFound = 0;
                if (dnsServerZone.ToLower().StartsWith("localdns"))
                {
                    dnsServerIP = dnsServerZone.Split(';')[1];
                    dnsZone = dnsServerZone.Split(';')[2];
                    string hostnameFQDN = String.Empty;
                    string endpoint = String.Empty;
                    List<string> output = new();
                    if (logLevel <= LogLevel.Information)
                        WriteLog("INF: Starting DNS zone transfer request on server " + dnsServerIP + " zone " + dnsZone);
                    using (Process process = new())
                    {
                        process.StartInfo.FileName = "nslookup";
                        process.StartInfo.UseShellExecute = false;
                        process.StartInfo.RedirectStandardInput = true;
                        process.StartInfo.RedirectStandardOutput = true;
                        process.Start();
                        process.StandardInput.WriteLine("server " + dnsServerIP);
                        process.StandardInput.WriteLine("set type=ANY");
                        process.StandardInput.WriteLine("ls -d " + dnsZone);
                        process.StandardInput.WriteLine("exit");
                        // Synchronously read the standard output of the spawned process.
                        using (StreamReader reader = process.StandardOutput)
                        {
                            while (!reader.EndOfStream)
                            {
                                output.Add(reader.ReadLine());
                            }
                        }
                        process.WaitForExit();
                    }

                    if (output == null)
                    {
                        if (logLevel <= LogLevel.Warning)
                            WriteLog("WRN: DNS zone transfer request on server " + dnsServerIP + " zone " + dnsZone + " returned nothing.");
                        continue;
                    }

                    foreach (string line in output)
                    {
                        if (line.Contains(" A      "))
                        {
                            hostnameFQDN = line.Substring(0, line.IndexOf(" A      ")).Trim() + "." + dnsZone;
                            endpoint = line.Substring(line.IndexOf(" A      ") + 8, line.Length - (line.IndexOf(" A      ") + 8)).Trim();
                        }
                        else if (line.Contains(" CNAME  "))
                        {
                            hostnameFQDN = line.Substring(0, line.IndexOf(" CNAME  ")).Trim() + "." + dnsZone;
                            endpoint = line.Substring(line.IndexOf(" CNAME  ") + 8, line.Length - (line.IndexOf(" CNAME  ") + 8)).Trim();
                        }
                        else
                            continue;

                        if (hostnameFQDN.Contains("..")) // Hardcoded filter to remove DNS server records
                        {
                            if (logLevel <= LogLevel.Debug)
                                WriteLog("DBG: Excluded by default: " + hostnameFQDN);
                            continue;
                        }
                        if (IsFqdnInFilter(hostnameFQDN))
                        {
                            if (logLevel <= LogLevel.Debug)
                                WriteLog("DBG: Excluded by filter: " + hostnameFQDN);
                            continue;
                        }
                        DataRow newRow = Globals.dtDNSrecs.NewRow();
                        newRow["hostnameFQDN"] = hostnameFQDN;
                        newRow["endpoint"] = endpoint;
                        newRow["dnsServerIP"] = dnsServerIP;
                        newRow["dnsZone"] = dnsZone;
                        Globals.dtDNSrecs.Rows.Add(newRow);
                        if (logLevel <= LogLevel.Information)
                            WriteLog("INF: Added record to scan: fqdn=" + hostnameFQDN + " endpoint=" + endpoint + " dnsserver=" + dnsServerIP + " dnszone=" + dnsZone);
                        recordsFound++;
                    }
                    if (logLevel <= LogLevel.Information)
                        WriteLog("INF: Finished DNS zone transfer request on server " + dnsServerIP + " zone " + dnsZone + ". " + recordsFound.ToString() + " A and CNAME records added to scan list");
                }
                else if (dnsServerZone.ToLower().StartsWith("azuredns"))
                {
                    
                    string subscriptionId = dnsServerZone.Split(';')[1];
                    string resourceGroupName = dnsServerZone.Split(';')[2];
                    dnsZone = dnsServerZone.Split(';')[3];
                    if (logLevel <= LogLevel.Information)
                        WriteLog("INF: Starting AzureDNS query on " + dnsZone + " in resource group " + resourceGroupName);
                    recordsFound = await GetAzureDNSRecords(subscriptionId, resourceGroupName, dnsZone);
                    if (logLevel <= LogLevel.Information)
                        WriteLog("INF: Finished AzureDNS query on " + dnsZone + " in resource group " + resourceGroupName + ". " + recordsFound.ToString() + " A and CNAME records added to scan list");
                }
                else
                {
                    if(logLevel <= LogLevel.Error) 
                        WriteLog("ERR: App.config DNSServerZone entry misconfigured: \"" + dnsServerZone + "\"");
                }
            }
            if (logLevel <= LogLevel.Information)
                WriteLog("INF: Starting scan of " + Globals.dtDNSrecs.Rows.Count.ToString() + " A and CNAME records on ports " + string.Join(",", Globals.portsToScan));

            // Add tasks for each port+ip to scan
            List<Task> tasks = new();
            foreach (string port in Globals.portsToScan)
            {
                foreach (DataRow row in Globals.dtDNSrecs.Rows)
                {
                    string hostnameFQDN = row["hostnameFQDN"].ToString();
                    if (hostnameFQDN.EndsWith("."))
                        hostnameFQDN = hostnameFQDN.Remove(hostnameFQDN.Length - 1);
                    string endpoint = row["endpoint"].ToString();
                    if (endpoint.EndsWith("."))
                        endpoint = endpoint.Remove(endpoint.Length - 1);
                    try
                    {
                        tasks.Add(Task.Run(async () => { await ScanForCertificateAsync(hostnameFQDN, endpoint, port, row["dnsServerIP"].ToString(), row["dnsZone"].ToString()); }));
                        if (tasks.Count > Globals.concurrentWebRequests) // Do tasks in bulks to not overload the system (this is not threads!)
                        {
                            Task t = Task.WhenAll(tasks);
                            t.Wait();
                            tasks.Clear();
                        }
                    }
                    catch (Exception ex)
                    {
                        if (logLevel <= LogLevel.Error)
                            WriteLog("ERR: Exception while doing tasks: " + ex.ToString());
                    }
                }
            }
            if (logLevel <= LogLevel.Information)
                WriteLog("INF: Certificate scan finished");
            File.WriteAllText(Globals.logLastRunFile, DateTime.Now.ToString()); // Log updated successful run datetime
#endregion

            #region ### CHECK CERTIFICATES FOUND AND SEND NOTIFICATION ###
            StringBuilder sb = new();
            DataTable dtAllCerts = GetSQLCertificates(); // Certificates found last 24h and ignore=0
            DataView dvCertificates = new(dtAllCerts)
            {
                Sort = "expiresDays ASC"
            };
            if (Globals.sendTrapNotification == "1")
            {
                dvCertificates.RowFilter = "expiresDays <= " + maxDaysThresholdCritical.ToString();
                if (dvCertificates.Count > 0) // Send trap for critical
                {
                    sb.Append("EXPIRING (DAYS:DOMAINNAME:ENDPOINT) ");
                    foreach (DataRowView drv in dvCertificates)
                    {
                        sb.Append("(" + drv["expiresDays"] + ":" + drv["hostnameFQDN"] + ":" + drv["endpoint"] + ")");
                    }
                    SendTrap(snmpServer, TrapStatus.Critical, sb.ToString());
                }
                else
                {
                    dvCertificates.RowFilter = "expiresDays <= " + maxDaysThresholdWarning.ToString();
                    if (dvCertificates.Count > 0) // Send trap for warning
                    {
                        sb.Append("EXPIRING (DAYS:DOMAINNAME:ENDPOINT) ");
                        foreach (DataRowView drv in dvCertificates)
                        {
                            sb.Append("(" + drv["expiresDays"] + ":" + drv["hostnameFQDN"] + ":" + drv["endpoint"] + ")");
                        }
                        SendTrap(snmpServer, TrapStatus.Warning, sb.ToString());
                    }
                }
                // No warning, critical or errors => send OK
                if (dvCertificates.Count == 0 && !Globals.hasErrorsCompleting)
                {
                    sb.Append("OK. No certificates found expiring in the next " + maxDaysThresholdWarning.ToString() + " days.");
                    SendTrap(snmpServer, TrapStatus.Normal, sb.ToString());
                }
            }

            if (Globals.sendEmailNotification == "1")
            {
                sb.Clear();
                dvCertificates.RowFilter = "expiresDays <= " + maxDaysThresholdCritical.ToString() + " AND expireWarning2Sent IS NULL";
                DataTable dtCritCert = dvCertificates.ToTable(false, "hostnameFQDN", "endpoint", "port", "dnsServerIP", "serialNumber", "issuerName", "issuedTo", "subjectName", "validFromDate", "expiresDate", "expiresDays", "detectedDate", "id");
                if (dtCritCert.Rows.Count > 0)
                {
                    sb.AppendLine("Certificates expiring in " + maxDaysThresholdCritical.ToString() + " days or less:");
                    sb.AppendLine(MakeHtmlTable(dtCritCert));
                }
                dvCertificates.RowFilter = "expiresDays <= " + maxDaysThresholdWarning.ToString() + " AND expiresDays > " + maxDaysThresholdCritical.ToString() + " AND expireWarning1Sent IS NULL";
                DataTable dtWarnCert = dvCertificates.ToTable(false, "hostnameFQDN", "endpoint", "port", "dnsServerIP", "serialNumber", "issuerName", "issuedTo", "subjectName", "validFromDate", "expiresDate", "expiresDays", "detectedDate", "id");
                if (dtWarnCert.Rows.Count > 0)
                {
                    sb.AppendLine("Certificates expiring in " + maxDaysThresholdWarning.ToString() + " days or less:");
                    sb.AppendLine(MakeHtmlTable(dtWarnCert));
                }
                if (sb.Length > 0)
                {
                    if(SendEmail(Globals.smtpFromAddress, Globals.smtpToAddresses, "CertificateScanner expiring certificates report", sb.ToString(), false))
                    {
                        foreach (DataRow row in dtWarnCert.Rows)
                        {
                            UpdateSqlCertEmailSent("expireWarning1Sent", row["id"].ToString());
                        }
                        foreach (DataRow row in dtCritCert.Rows)
                        {
                            UpdateSqlCertEmailSent("expireWarning2Sent", row["id"].ToString());
                        }
                    }
                }
            }
            if (logLevel <= LogLevel.Information)
                WriteLog("INF: Script completed");

            #endregion
        }
        private static void UpdateSqlCertEmailSent(string columnName, string id)
        {
            try
            {
                using SqlConnection connection = new(Globals.sqlConnectionString);
                SqlCommand command = new("UPDATE " + Globals.certificatesLogTable + " SET " + columnName + " = GETDATE() WHERE (id = N'" + id + "')", connection);
                connection.Open();
                command.ExecuteNonQuery();
                connection.Close();
            }
            catch (Exception ex)
            {
                if (logLevel <= LogLevel.Warning)
                    WriteLog("WRN: UpdateSqlCertEmailSent() Unable to datestamp id:" + id + ". Column:"+ columnName + ". Check SQL connection. Exception was: " + ex.ToString());
            }
        }
        private static string MakeHtmlTable(DataTable dt)
        {
            string[] table = new string[dt.Rows.Count + 1];
            long counter = 2;
            table[0] = "<tr><th>" + string.Join("</th><th>", (from a_Col in dt.Columns.Cast<DataColumn>() select a_Col.ColumnName).ToArray()) + "</th></tr>";
            foreach (DataRow row in dt.Rows)
            {
                table[counter - 1] = "<tr><td>" + String.Join("</td><td>", (from o in row.ItemArray select o.ToString()).ToArray()) + "</td></tr>";
                counter += 1;
            }
            return "<table border=\"1\">" + String.Join("", table) + "</table></br>";
        }
        private static async Task<int> GetAzureDNSRecords(string subscriptionId, string resourceGroupName, string dnsZone)
        {
            int recordsFound = 0;
            try
            {
                ArmClient armClient = new(new ClientSecretCredential(Globals.tenantId, Globals.clientId, Globals.secret));
                ResourceIdentifier armResouceIdDnsZone = new("/subscriptions/" + subscriptionId + "/resourceGroups/" + resourceGroupName + "/providers/Microsoft.Network/dnszones/" + dnsZone);
                DnsZoneResource dnsZoneResource = armClient.GetDnsZoneResource(armResouceIdDnsZone);
                await foreach (DnsRecordData record in dnsZoneResource.GetAllRecordDataAsync())
                {
                    switch (record.ResourceType)
                    {
                        case "Microsoft.Network/dnszones/A":
                            {
                                foreach (var aRecord in record.DnsARecords)
                                {
                                    string fqdn = record.Fqdn.TrimEnd('.');
                                    if (IsFqdnInFilter(fqdn))
                                    {
                                        if (logLevel <= LogLevel.Information)
                                            WriteLog("INF: Excluded by filter: " + fqdn);
                                        continue;
                                    }
                                    DataRow newRow = Globals.dtDNSrecs.NewRow();
                                    newRow["hostnameFQDN"] = fqdn;
                                    newRow["endpoint"] = aRecord.IPv4Address.ToString();
                                    newRow["dnsServerIP"] = resourceGroupName;
                                    newRow["dnsZone"] = dnsZone;
                                    Globals.dtDNSrecs.Rows.Add(newRow);
                                    if (logLevel <= LogLevel.Information)
                                        WriteLog("INF: Added A record to scan: fqdn=" + fqdn + " endpoint=" + aRecord.IPv4Address.ToString() + " dnsserver=" + resourceGroupName + " dnszone=" + dnsZone);
                                    recordsFound++;
                                }
                                break;
                            }
                        case "Microsoft.Network/dnszones/CNAME":
                            {
                                string fqdn = record.Fqdn.TrimEnd('.');
                                if (IsFqdnInFilter(fqdn))
                                {
                                    if (logLevel <= LogLevel.Information)
                                        WriteLog("INF: Excluded by filter: " + fqdn);
                                    continue;
                                }
                                DataRow newRow = Globals.dtDNSrecs.NewRow();
                                newRow["hostnameFQDN"] = fqdn;
                                newRow["endpoint"] = record.Cname;
                                newRow["dnsServerIP"] = resourceGroupName;
                                newRow["dnsZone"] = dnsZone;
                                Globals.dtDNSrecs.Rows.Add(newRow);
                                if (logLevel <= LogLevel.Information)
                                    WriteLog("INF: Added CNAME record to scan: fqdn=" + fqdn + " endpoint=" + record.Cname + " dnsserver=" + resourceGroupName + " dnszone=" + dnsZone);
                                recordsFound++;
                                break;
                            }
                        default:
                            break;
                    }
                }
            }
            catch (Exception ex)
            {
                if (logLevel <= LogLevel.Error)
                    WriteLog("ERR: GetAzureDNSRecords() Exception: " + ex.ToString());
            }
            return recordsFound;
        }
        private static bool IsFqdnInFilter(string fqdn)
        {
            fqdn = fqdn.ToLower();
            foreach (string filter in Globals.filters)
            {
                Regex exName = new(filter);
                if(exName.IsMatch(fqdn))
                    return true;
            }
            return false;
        }
        public static void SendTrap(string serverIp, TrapStatus status, string message)
        {
            try
            {
                int intStatus = (int)status;
                ObjectIdentifier oID = new("2.25.999." + intStatus.ToString());
                IPEndPoint ipManager = new(IPAddress.Parse(serverIp), 162);
                List<Variable> SNMPVariables = new();
                Variable var1 = new(oID, new OctetString(message));
                SNMPVariables.Add(var1);
                Messenger.SendTrapV2(0, VersionCode.V2, ipManager, new OctetString("public"), oID, 0, SNMPVariables);
                if (logLevel <= LogLevel.Information)
                    WriteLog("INF: Sent SNMP trap message \"" + message + "\" with status " + status.ToString() + " to SNMP server " + serverIp);
            }
            catch (Exception ex)
            {
                if (logLevel <= LogLevel.Error)
                    WriteLog("ERR: SendTrap() Exception: " + ex.ToString());
            }
        }
        public static bool SendEmail(string from, string commaSeperatedRecipients, string subject, string body, bool sendAsBcc)
        {
            try
            {
                MailMessage msg = new();
                MailAddressCollection recipientCollection = new();
                foreach (string mailaddress in commaSeperatedRecipients.Split(new[] { "," }, StringSplitOptions.RemoveEmptyEntries))
                {
                    MailAddress recipient = new(mailaddress);
                    recipientCollection.Add(recipient);
                }
                MailAddress fromAddress = new(from);
                msg.From = fromAddress;
                msg.Subject = subject;
                msg.Body = body;
                msg.IsBodyHtml = true;
                if (sendAsBcc)
                {
                    msg.To.Add(fromAddress); // Set self as recipient
                    msg.Bcc.Add(recipientCollection.ToString());
                }
                else
                {
                    msg.To.Add(recipientCollection.ToString());
                }

                var credential = new NetworkCredential(Globals.smtpUsername, Globals.smtpPassword);
                SmtpClient client = new(Globals.smtpServer.Split(':')[0])
                {
                    Credentials = credential,
                    Port = int.Parse(Globals.smtpServer.Split(':')[1])
                };
                client.Send(msg);
                if (logLevel <= LogLevel.Information)
                    WriteLog("INF: Sent SMTP message to server " + Globals.smtpServer + " with subject \"" + subject + "\" to " + commaSeperatedRecipients);
                return true;
            }
            catch (Exception ex)
            {
                if (logLevel <= LogLevel.Error)
                    WriteLog("ERR: SendEmail() exception: " + ex.ToString());
            }
            return false;
        }
        public static DataTable GetSQLCertificates()
        {
            DataTable dt = new();
            try
            {
                using SqlConnection connection = new(Globals.sqlConnectionString);
                SqlDataAdapter da = new("SELECT * " +
                                        "FROM " + Globals.certificatesLogTable + " " +
                                        "WHERE (lastScannedDate > '" + GetDateTimeSQLString(DateTime.Now.AddDays(-1)) + "') AND (ignore = 0)", connection);
                da.Fill(dt);
            }
            catch (Exception ex)
            {
                if (logLevel <= LogLevel.Error)
                    WriteLog("ERR: GetSQLCertificates() Exception: " + ex.ToString());
            }
            return dt;
        }
        private static async Task<X509Certificate2> GetServerCertificateAsync(Uri url)
        {
            try
            {
                X509Certificate2 certificate = null;
                HttpClientHandler httpClientHandler = new()
                {
                    AllowAutoRedirect = false,
                    CheckCertificateRevocationList = false,
                    SslProtocols = System.Security.Authentication.SslProtocols.Tls | System.Security.Authentication.SslProtocols.Tls11 | System.Security.Authentication.SslProtocols.Tls12,
                    ServerCertificateCustomValidationCallback = (_, cert, __, ___) =>
                    {
                        certificate = new X509Certificate2(cert.GetRawCertData());
                        return true;
                    }
                };
                HttpClient httpClient = new(httpClientHandler)
                {
                    Timeout = Globals.httpClientTimeout // Timeout in ms configurable in .config
                };
                await httpClient.SendAsync(new HttpRequestMessage(HttpMethod.Head, url));
                return certificate;
            }
            catch (HttpRequestException ex)
            {
                // Expected exceptions
                if (ex.Message == "An error occurred while sending the request." && ex.InnerException.Message == "Unable to connect to the remote server")
                {
                    if (logLevel <= LogLevel.Trace) 
                        WriteLog("TRC: GetServerCertificateAsync() known exception: Unable to connect to the remote server: " + url.Host + ":" + url.Port);
                    return null;
                }
                if (ex.Message == "An error occurred while sending the request." && ex.InnerException.Message == "The underlying connection was closed: An unexpected error occurred on a send.")
                {
                    if (logLevel <= LogLevel.Trace) 
                        WriteLog("TRC: GetServerCertificateAsync() known exception: The underlying connection was closed: An unexpected error occurred on a send: " + url.Host + ":" + url.Port);
                    return null;
                }
                if (ex.Message == "An error occurred while sending the request." && ex.InnerException.Message == "The underlying connection was closed: An unexpected error occurred on a receive.")
                {
                    if (logLevel <= LogLevel.Trace) 
                        WriteLog("TRC: GetServerCertificateAsync() known exception: The underlying connection was closed: An unexpected error occurred on a receive: " + url.Host + ":" + url.Port);
                    return null;
                }
                if (ex.Message == "An error occurred while sending the request." && ex.InnerException.Message == "The request was aborted: The request was canceled.")
                {
                    if (logLevel <= LogLevel.Trace)
                        WriteLog("TRC: GetServerCertificateAsync() known exception: The request was aborted: The request was canceled.: " + url.Host + ":" + url.Port);
                    return null;
                }
                if (ex.Message == "An error occurred while sending the request." && ex.InnerException.Message.Contains("The remote name could not be resolved"))
                {
                    if (logLevel <= LogLevel.Trace)
                        WriteLog("TRC: GetServerCertificateAsync() known exception: The remote name could not be resolved: " + url.Host + ":" + url.Port);
                    return null;
                }
                if (ex.Message == "The SSL connection could not be established, see inner exception." && ex.InnerException.Message.Contains("An existing connection was forcibly closed by the remote host"))
                {
                    if (logLevel <= LogLevel.Trace)
                        WriteLog("TRC: GetServerCertificateAsync() known exception: An existing connection was forcibly closed by the remote host: " + url.Host + ":" + url.Port);
                    return null;
                }
                if (ex.Message.Contains("No connection could be made because the target machine actively refused it.") && ex.InnerException.Message.Contains("No connection could be made because the target machine actively refused it."))
                {
                    if (logLevel <= LogLevel.Trace)
                        WriteLog("TRC: GetServerCertificateAsync() known exception: No connection could be made because the target machine actively refused it: " + url.Host + ":" + url.Port);
                    return null;
                }
                if (logLevel <= LogLevel.Warning)
                    WriteLog("WRN: GetServerCertificateAsync() unknown HttpRequestException connecting to " + url.AbsoluteUri + ":" + url.Port + " :" + ex.ToString());
            }
            catch (TaskCanceledException ex)
            {
                // Expected exceptions
                if (ex.Message == "A task was canceled.")
                {
                    // Timeouts - browsing these hosts usually return ERR_CONNECTION_TIMED_OUT
                    if (logLevel <= LogLevel.Trace)
                        WriteLog("TRC: GetServerCertificateAsync() known exception: A task was canceled: " + url.Host + ":" + url.Port);
                    return null;
                }
            }
            catch (Exception ex) 
            {
                if(logLevel <= LogLevel.Warning)
                    WriteLog("WRN: GetServerCertificateAsync() unknown Exception connecting to " + url.AbsoluteUri + ":" + url.Port + " :" + ex.ToString());
            }
            return null;
        }
        private static async Task ScanForCertificateAsync(string hostnameFQDN, string endpoint, string port, string dnsServerIP, string dnsServerZone)
        {
            try
            {
                Uri requestFqdnUri = new UriBuilder(Uri.UriSchemeHttps, hostnameFQDN, int.Parse(port)).Uri;
                Uri requestIpUri = new UriBuilder(Uri.UriSchemeHttps, endpoint, int.Parse(port)).Uri;
                // Alternative: doing requestFqdnUri first does not support split DNS zones, need to implement a way to use specific DNS resolvers
                X509Certificate2 cert2 = await GetServerCertificateAsync(requestIpUri);
                if (cert2 == null) // No initial certificate found, retry with fqdn request
                {
                    cert2 = await GetServerCertificateAsync(requestFqdnUri);
                    if (cert2 != null)
                    {
                        if (logLevel <= LogLevel.Information)
                            WriteLog("INF: No certificate returned from " + requestIpUri.AbsoluteUri + ":" + port + " but found on " + requestFqdnUri.AbsoluteUri + ":" + port);
                    }
                }
                else if ((cert2.SubjectName.Name.Contains(".azurewebsites.") || (cert2.SubjectName.Name.Contains(".msappproxy.")))) 
                {
                    // Azure Webapps returns a *.azurewebsites.* certificate, and Azure app proxy a *.msappproxy.* certificate when querying by ip.
                    // Check if there is a custom domain certificate with a hostnameFQDN request, and use that if exists instead
                    requestFqdnUri = new UriBuilder(Uri.UriSchemeHttps, hostnameFQDN, int.Parse(port)).Uri;
                    X509Certificate2 tempCertificate = await GetServerCertificateAsync(requestFqdnUri);
                    if (tempCertificate != null)
                    {
                        if (logLevel <= LogLevel.Information)
                            WriteLog("INF: Azure certificate found on Uri " + requestIpUri.AbsoluteUri + ":" + port + " but was replaced with certificate from Uri " + requestFqdnUri.AbsoluteUri + ":" + port);
                        cert2 = tempCertificate;
                    }
                }
                
                if(cert2 != null)
                {
                    string issuerName = cert2.IssuerName.Name;
                    string issuedTo = cert2.GetNameInfo(X509NameType.SimpleName, false);
                    string subjectName = cert2.SubjectName.Name;
                    DateTime validFromDate = DateTime.Parse(cert2.GetEffectiveDateString());
                    DateTime expireDate = DateTime.Parse(cert2.GetExpirationDateString());
                    string signatureAlgorithm = cert2.SignatureAlgorithm.FriendlyName;
                    string serialNumber = cert2.SerialNumber;
                    string subjectAlternativeNames = "";
                    int expiresDays = 0;
                    bool alreadyRegisteredInSQL = false;

                    foreach (X509Extension extension in cert2.Extensions)
                    {
                        if (extension.Oid.Value == "2.5.29.17") // Subject alternative names
                        {
                            string extensionString = extension.Format(true);
                            subjectAlternativeNames += extensionString.Replace(Environment.NewLine, ",");
                        }
                    }
                    if (subjectAlternativeNames.EndsWith(","))
                        subjectAlternativeNames = subjectAlternativeNames.Remove(subjectAlternativeNames.Length - 1, 1);

                    TimeSpan ts = new();
                    ts = expireDate - DateTime.Now;
                    expiresDays = ts.Days;

                    // Check if certificate already exists in sql. Match on hostnameFQDN && port && endpoint && serialnumber to identifiy split dns and server name indication scenarios
                    using SqlConnection connection = new(Globals.sqlConnectionString);
                    string sqlGetCertificateInfo = "SELECT COUNT(*) AS Expr1 FROM " + Globals.certificatesLogTable + " WHERE (hostnameFQDN = N'" + hostnameFQDN + "') AND (port = N'" + port + "') AND (endpoint = N'" + endpoint + "') AND (serialNumber = N'" + serialNumber + "')";
                    SqlCommand sqlSelectCountCmd = new(sqlGetCertificateInfo, connection);
                    connection.Open();
                    int result = (int)sqlSelectCountCmd.ExecuteScalar();
                    if (result > 0)
                    {
                        alreadyRegisteredInSQL = true;
                        // Update LastScanned record in database
                        string sqlUpdateCertificateInfoLastScanned = "UPDATE " + Globals.certificatesLogTable + " SET lastScannedDate = { fn NOW() }, expiresDays = @expiresDays, subjectAlternativeNames = @subjectAlternativeNames  WHERE (hostnameFQDN = @hostnameFQDN) AND (port = @port) AND (endpoint = @endpoint) AND (serialNumber = @serialNumber)";
                        SqlCommand sqlUpdateCmd = new(sqlUpdateCertificateInfoLastScanned, connection);
                        sqlUpdateCmd.Parameters.AddWithValue("@hostnameFQDN", hostnameFQDN);
                        sqlUpdateCmd.Parameters.AddWithValue("@port", port);
                        sqlUpdateCmd.Parameters.AddWithValue("@endpoint", endpoint);
                        sqlUpdateCmd.Parameters.AddWithValue("@expiresDays", expiresDays);
                        sqlUpdateCmd.Parameters.AddWithValue("@serialNumber", serialNumber);
                        sqlUpdateCmd.Parameters.AddWithValue("@subjectAlternativeNames", subjectAlternativeNames);
                        sqlUpdateCmd.ExecuteNonQuery();
                        if (logLevel <= LogLevel.Trace)
                            WriteLog("TRC: Certificate updated in sql. fqdn=" + hostnameFQDN + " port:" + port + " endpoint:" + endpoint + " subjectName=\"" + subjectName + "\" serialNumber=" + serialNumber);
                    }
                    if (!alreadyRegisteredInSQL) // If not in database, then add it
                    {
                        string validFromSQLTime = GetDateTimeSQLString(validFromDate);
                        string expiresDateSQLTime = GetDateTimeSQLString(expireDate);
                        string sqlInsertCertificateInfo = "INSERT INTO " + Globals.certificatesLogTable + " " +
                            "(hostnameFQDN, endpoint, port, dnsServerIP, dnsServerZone, serialNumber, issuerName, issuedTo, subjectName, validFromDate, expiresDate, expiresDays, signatureAlgorithm, subjectAlternativeNames, lastScannedDate) VALUES " +
                            "(@hostnameFQDN, @endpoint, @port, @dnsServerIP, @dnsServerZone, @serialNumber, @issuerName, @issuedTo , @subjectName, @validFromSQLTime, @expiresDateSQLTime, @expiresDays, @signatureAlgorithm, @subjectAlternativeNames, @lastScannedDate)";
                        SqlCommand sqlInsertCmd = new(sqlInsertCertificateInfo, connection);
                        sqlInsertCmd.Parameters.AddWithValue("@hostnameFQDN", hostnameFQDN);
                        sqlInsertCmd.Parameters.AddWithValue("@endpoint", endpoint);
                        sqlInsertCmd.Parameters.AddWithValue("@port", port);
                        sqlInsertCmd.Parameters.AddWithValue("@dnsServerIP", dnsServerIP);
                        sqlInsertCmd.Parameters.AddWithValue("@dnsServerZone", dnsServerZone);
                        sqlInsertCmd.Parameters.AddWithValue("@serialNumber", serialNumber);
                        sqlInsertCmd.Parameters.AddWithValue("@issuerName", issuerName);
                        sqlInsertCmd.Parameters.AddWithValue("@issuedTo", issuedTo);
                        sqlInsertCmd.Parameters.AddWithValue("@subjectName", subjectName);
                        sqlInsertCmd.Parameters.AddWithValue("@validFromSQLTime", validFromSQLTime);
                        sqlInsertCmd.Parameters.AddWithValue("@expiresDateSQLTime", expiresDateSQLTime);
                        sqlInsertCmd.Parameters.AddWithValue("@expiresDays", expiresDays);
                        sqlInsertCmd.Parameters.AddWithValue("@signatureAlgorithm", signatureAlgorithm);
                        sqlInsertCmd.Parameters.AddWithValue("@subjectAlternativeNames", subjectAlternativeNames);
                        sqlInsertCmd.Parameters.AddWithValue("@lastScannedDate", GetDateTimeSQLString(DateTime.Now));
                        connection.Open();
                        sqlInsertCmd.ExecuteNonQuery();
                        if (logLevel <= LogLevel.Trace)
                            WriteLog("TRC: Certificate added to sql. fqdn=" + hostnameFQDN + " port:" + port + " endpoint:" + endpoint + " subjectName=\"" + subjectName + "\" serialNumber=" + serialNumber);
                    }
                    connection.Close();
                }
                else
                {
                    if (logLevel <= LogLevel.Debug)
                        WriteLog("DBG: No certificate returned from endpoint " + endpoint + ":" + port + " or fqdn " + hostnameFQDN + ":" + port);
                }
            }
            catch (Exception ex)
            {
                if (logLevel <= LogLevel.Error)
                    WriteLog("ERR: ScanForCertificate(" + hostnameFQDN + "," + endpoint + "," + port + "," + dnsServerIP + "," + dnsServerZone + ") Exception: " + ex.ToString());
            }
        }
        private static string GetDateTimeSQLString(DateTime SomeTime)
        {
            //yyyy-MM-dd HH:mm:ss
            string SqlTime = SomeTime.Year.ToString() + "-" + SomeTime.Month.ToString() + "-" + SomeTime.Day.ToString() + " " + SomeTime.Hour.ToString() + ":" + SomeTime.Minute + ":" + SomeTime.Second.ToString();
            return SqlTime;
        }
        private static void WriteLog(string logText)
        {
            try
            {
                string logTime = DateTime.Now.ToString("yyyy-MM-dd");
                string logFile = Globals.logFile.Replace("DATE", logTime);
                string outputText = logTime + DateTime.Now.ToString(" HH:mm:ss ") + logText;
#if !DEBUG
                if (!File.Exists(logFile))
                {
                    using StreamWriter sw = File.CreateText(logFile);
                    sw.WriteLine(outputText);
                }
                else
                {
                    using StreamWriter sw = File.AppendText(logFile);
                    sw.WriteLine(outputText);
                }
#else
                Console.WriteLine(outputText);
#endif
            }
            catch (Exception)
            {
#if DEBUG
                Console.WriteLine("ERR: Unable to write to logfile.");
#endif
            }
        }
    }
}
