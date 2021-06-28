using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Messaging;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.Data.SqlClient;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Rest.Azure.Authentication;
using Microsoft.Azure.Management.Dns;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Text.RegularExpressions;
using System.Net.Mail;

namespace CertificateScanner
{
    public class Globals
    {
        public static FileInfo appStartPath = new FileInfo(new Uri(Assembly.GetExecutingAssembly().CodeBase).LocalPath);
        public static string logLastRunFile = appStartPath.DirectoryName + @"\LogLastRun.txt";
        public static string logFile = appStartPath.DirectoryName + @"\logs\DATE.txt";
        public static bool hasErrorsCompleting = false;
        public static string certificatesLogTable = "certificatesLog";

        // Read from App.config
        public static string tenantId;
        public static string clientId;
        public static string secret;
        public static List<string> portsToScan;
        public static List<string> filters = new List<string>();
        public static string sendEmailNotification;
        public static string smtpServer;
        public static string smtpUsername;
        public static string smtpPassword;
        public static string smtpFromAddress;
        public static string smtpToAddresses;
        public static string sendTrapNotification;
        public static string sqlConnectionString;
        public static int httpWebRequestTimeout;

        // DataTable to store DNS records found in the different zones
        public static DataTable dtDNSrecs = new DataTable();
    }

    class Program
    {
        [DllImport("dnsapi.dll", EntryPoint = "DnsFlushResolverCache")]
        private static extern UInt32 DnsFlushResolverCache();

        public static void FlushDNSCache()
        {
            uint result = DnsFlushResolverCache();
        }

        public enum LogLevel { Trace = 0, Debug = 1, Information = 2, Warning = 3, Error = 4, Critical = 5, None = 6 }
        public static LogLevel logLevel = LogLevel.Information;
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
            List<string> azureDnsServerZones = new List<string>();
            List<string> dnsServerZones = new List<string>();
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
                maxErrorDaysThreshold = int.Parse(ConfigurationManager.AppSettings["MaxErrorDaysThreshold"]);
                maxDaysThresholdWarning = int.Parse(ConfigurationManager.AppSettings["MaxDaysThresholdWarning"]);
                maxDaysThresholdCritical = int.Parse(ConfigurationManager.AppSettings["MaxDaysThresholdCritical"]);
                Globals.httpWebRequestTimeout = int.Parse(ConfigurationManager.AppSettings["HttpWebRequestTimeout"]);
                Enum.TryParse(ConfigurationManager.AppSettings["LogLevel"], out LogLevel logLevel);
                foreach (string key in ConfigurationManager.AppSettings)
                {
                    if (key.ToLower().StartsWith("dnsserverzone"))
                        dnsServerZones.Add(ConfigurationManager.AppSettings[key]);
                    if (key.ToLower().StartsWith("regexfilter"))
                        Globals.filters.Add(ConfigurationManager.AppSettings[key]);
                }
            }
            catch (Exception ex)
            {
                if (logLevel <= LogLevel.Error)
                    WriteLog("ERR: Failed to read configuration Exception: " + ex.ToString());
            }
#endregion

#region ### LAST RUN CHECK ###
            // Last run check, send trap if we have been unable to complete a certificate scan for X days
            DateTime lastRun = new DateTime();
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
                    List<string> output = new List<string>();
                    if (logLevel <= LogLevel.Information)
                        WriteLog("INF: Starting DNS zone transfer request on server " + dnsServerIP + " zone " + dnsZone);
                    using (Process process = new Process())
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

            var tasks = new List<Task>();

            // Add tasks for each port+ip to scan
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
                    tasks.Add(Task.Run(() => { ScanForCertificate(hostnameFQDN, endpoint, port, row["dnsServerIP"].ToString(), row["dnsZone"].ToString()); }));
                }
            }
            Task t = Task.WhenAll(tasks);
            try
            {
                t.Wait();
            }
            catch { }
            if (t.Status == TaskStatus.RanToCompletion)
            {
                if (logLevel <= LogLevel.Information)
                    WriteLog("INF: Scan completed successfully");
            }
            else if (t.Status == TaskStatus.Faulted)
            {
                if (logLevel <= LogLevel.Information)
                    WriteLog("INF: Scan completed with errors");
            }
            File.WriteAllText(Globals.logLastRunFile, DateTime.Now.ToString()); // Log updated successful run datetime
#endregion

#region ### CHECK CERTIFICATES FOUND AND SEND NOTIFICATION ###
            StringBuilder sb = new StringBuilder();
            DataTable dtAllCerts = GetSQLCertificates(); // Certificates found last 24h and ignore=0
            DataView dvCertificates = new DataView(dtAllCerts)
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

#endregion
        }
        private static void UpdateSqlCertEmailSent(string columnName, string id)
        {
            try
            {
                using (SqlConnection connection = new SqlConnection(Globals.sqlConnectionString))
                {
                    SqlCommand command = new SqlCommand("UPDATE certificatesLog SET " + columnName + " = GETDATE() WHERE (id = N'" + id + "')", connection);
                    connection.Open();
                    command.ExecuteNonQuery();
                    connection.Close();
                }
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
            var serviceCreds = await ApplicationTokenProvider.LoginSilentAsync(Globals.tenantId, Globals.clientId, Globals.secret);
            var dnsClient = new DnsManagementClient(serviceCreds)
            {
                SubscriptionId = subscriptionId
            };
            var page = await dnsClient.RecordSets.ListAllByDnsZoneAsync(resourceGroupName, dnsZone);
            while (true)
            {
                foreach (var record in page)
                {
                    if (record.Type == "Microsoft.Network/dnszones/A")
                    {
                        foreach (var aRecord in record.ARecords)
                        {
                            if (IsFqdnInFilter(record.Fqdn))
                            {
                                if (logLevel <= LogLevel.Debug)
                                    WriteLog("DBG: Excluded by filter: " + record.Fqdn);
                                continue;
                            }
                            DataRow newRow = Globals.dtDNSrecs.NewRow();
                            newRow["hostnameFQDN"] = record.Fqdn;
                            newRow["endpoint"] = aRecord.Ipv4Address;
                            newRow["dnsServerIP"] = resourceGroupName;
                            newRow["dnsZone"] = dnsZone;
                            Globals.dtDNSrecs.Rows.Add(newRow);
                            recordsFound++;
                        }
                    }
                    else if (record.Type == "Microsoft.Network/dnszones/CNAME")
                    {
                        if (IsFqdnInFilter(record.Fqdn))
                        {
                            if (logLevel <= LogLevel.Debug)
                                WriteLog("DBG: Excluded by filter: " + record.Fqdn);
                            continue;
                        }
                        DataRow newRow = Globals.dtDNSrecs.NewRow();
                        newRow["hostnameFQDN"] = record.Fqdn;
                        newRow["endpoint"] = record.CnameRecord.Cname;
                        newRow["dnsServerIP"] = resourceGroupName;
                        newRow["dnsZone"] = dnsZone;
                        Globals.dtDNSrecs.Rows.Add(newRow);
                        recordsFound++;
                    }
                }
                if (string.IsNullOrEmpty(page.NextPageLink))
                {
                    break;
                }
                page = await dnsClient.RecordSets.ListAllByDnsZoneNextAsync(page.NextPageLink);
            }
            return recordsFound;
        }
        private static bool IsFqdnInFilter(string fqdn)
        {
            fqdn = fqdn.ToLower();
            foreach (string filter in Globals.filters)
            {
                Regex exName = new Regex(filter);
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
                ObjectIdentifier oID = new ObjectIdentifier("2.25.999." + intStatus.ToString());
                IPEndPoint ipManager = new IPEndPoint(IPAddress.Parse(serverIp), 162);
                List<Variable> SNMPVariables = new List<Variable>();
                Variable var1 = new Variable(oID, new OctetString(message));
                SNMPVariables.Add(var1);
#if !DEBUG
                Messenger.SendTrapV2(0, VersionCode.V2, ipManager, new OctetString("public"), oID, 0, SNMPVariables);
#endif
            }
            catch (Exception ex)
            {
                if (logLevel <= LogLevel.Error)
                    WriteLog("WRN: SendTrap() Exception: " + ex.ToString());
            }
        }
        public static bool SendEmail(string from, string commaSeperatedRecipients, string subject, string body, bool sendAsBcc)
        {
            try
            {
                MailMessage msg = new MailMessage();
                MailAddressCollection recipientCollection = new MailAddressCollection();
                foreach (string mailaddress in commaSeperatedRecipients.Split(new[] { "," }, StringSplitOptions.RemoveEmptyEntries))
                {
                    MailAddress recipient = new MailAddress(mailaddress);
                    recipientCollection.Add(recipient);
                }
                MailAddress fromAddress = new MailAddress(from);
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
                SmtpClient client = new SmtpClient(Globals.smtpServer.Split(':')[0])
                {
                    Credentials = credential,
                    Port = int.Parse(Globals.smtpServer.Split(':')[1])
                };
                client.Send(msg);
                return true;
            }
            catch (Exception ex)
            {
                if (logLevel <= LogLevel.Warning)
                    WriteLog("WRN: SendEmail() exception: " + ex.ToString());
            }
            return false;
        }
        public static DataTable GetSQLCertificates()
        {
            DataTable dt = new DataTable();
            try
            {
                using (SqlConnection connection = new SqlConnection(Globals.sqlConnectionString))
                {
                    SqlDataAdapter da = new SqlDataAdapter("SELECT * " +
                                                           "FROM            certificatesLog " +
                                                           "WHERE (lastScannedDate > '" + GetDateTimeSQLString(DateTime.Now.AddDays(-1)) + "') AND (ignore = 0)", connection);
                    da.Fill(dt);
                }
            }
            catch (Exception ex)
            {
                if (logLevel <= LogLevel.Warning)
                    WriteLog("WRN: GetSQLCertificates() Exception: " + ex.ToString());
            }
            return dt;
        }
        private static void ScanForCertificate(string hostnameFQDN, string endpoint, string port, string dnsServerIP, string dnsServerZone)
        {
            try
            {
                // Ignore SSL errors
                ServicePointManager.ServerCertificateValidationCallback = new System.Net.Security.RemoteCertificateValidationCallback(AcceptAllCertifications);

                var ipUri = new UriBuilder(Uri.UriSchemeHttps, endpoint, int.Parse(port)).Uri;
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(ipUri);
                request.Host = hostnameFQDN;

                request.AllowAutoRedirect = false;
                request.Timeout = Globals.httpWebRequestTimeout; // Timeout in ms configurable in .config

                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                response.Close();

                // Get the ssl cert and assign it to an X509Certificate object
                X509Certificate cert = request.ServicePoint.Certificate;

                // Convert the X509Certificate to an X509Certificate2 object by passing it into the constructor
                X509Certificate2 cert2 = new X509Certificate2(cert);

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
                        String stringSubjectAltName = extension.Format(true);
                        subjectAlternativeNames = subjectAlternativeNames.Replace(Environment.NewLine, " # ");
                        if (subjectAlternativeNames.EndsWith(" # "))
                            subjectAlternativeNames.Remove(subjectAlternativeNames.Length - 3, 3);
                    }
                }
                TimeSpan ts = new TimeSpan();
                ts = expireDate - DateTime.Now;
                expiresDays = ts.Days;

                // Optional: skip re-adding certificats already expired more than 30 days ago
                //if (expiresDays < -30)
                //    return;

                // Check if certificate already exists in sql. Match on hostnameFQDN && port && endpoint && serialnumber to identifiy split dns and server name indication scenarios
                using (SqlConnection connection = new SqlConnection(Globals.sqlConnectionString))
                {
                    string sqlGetCertificateInfo = "SELECT COUNT(*) AS Expr1 FROM " + Globals.certificatesLogTable + " WHERE (hostnameFQDN = N'" + hostnameFQDN + "') AND (port = N'" + port + "') AND (endpoint = N'" + endpoint + "') AND (serialNumber = N'" + serialNumber + "')";
                    SqlCommand sqlCmd = new SqlCommand(sqlGetCertificateInfo, connection);
                    connection.Open();
                    int result = (int)sqlCmd.ExecuteScalar();
                    if (result > 0)
                    {
                        alreadyRegisteredInSQL = true;
                        // Update LastScanned record in database
                        string sqlUpdateCertificateInfoLastScanned = "UPDATE " + Globals.certificatesLogTable + " SET lastScannedDate = { fn NOW() }, expiresDays = @expiresDays, subjectAlternativeNames = @subjectAlternativeNames  WHERE (hostnameFQDN = @hostnameFQDN) AND (endpoint = @endpoint) AND (serialNumber = @serialNumber)";
                        SqlCommand sqlCmd2 = new SqlCommand(sqlUpdateCertificateInfoLastScanned, connection);
                        sqlCmd2.Parameters.AddWithValue("@hostnameFQDN", hostnameFQDN);
                        sqlCmd2.Parameters.AddWithValue("@endpoint", endpoint);
                        sqlCmd2.Parameters.AddWithValue("@expiresDays", expiresDays);
                        sqlCmd2.Parameters.AddWithValue("@serialNumber", serialNumber);
                        sqlCmd2.Parameters.AddWithValue("@subjectAlternativeNames", subjectAlternativeNames);
                        sqlCmd2.ExecuteNonQuery();
                    }
                    connection.Close();
                }
                if (!alreadyRegisteredInSQL) // If not in database, then add it
                {
                    using (SqlConnection connection = new SqlConnection(Globals.sqlConnectionString))
                    {
                        string validFromSQLTime = GetDateTimeSQLString(validFromDate);
                        string expiresDateSQLTime = GetDateTimeSQLString(expireDate);
                        string sqlInsertCertificateInfo = "INSERT INTO " + Globals.certificatesLogTable + " " +
                            "(hostnameFQDN, endpoint, port, dnsServerIP, dnsServerZone, serialNumber, issuerName, issuedTo, subjectName, validFromDate, expiresDate, expiresDays, signatureAlgorithm, subjectAlternativeNames) VALUES " +
                            "(@hostnameFQDN, @endpoint, @port, @dnsServerIP, @dnsServerZone, @serialNumber, @issuerName, @issuedTo , @subjectName, @validFromSQLTime, @expiresDateSQLTime, @expiresDays, @signatureAlgorithm, @subjectAlternativeNames)";
                        SqlCommand sqlCmd = new SqlCommand(sqlInsertCertificateInfo, connection);
                        sqlCmd.Parameters.AddWithValue("@hostnameFQDN", hostnameFQDN);
                        sqlCmd.Parameters.AddWithValue("@endpoint", endpoint);
                        sqlCmd.Parameters.AddWithValue("@port", port);
                        sqlCmd.Parameters.AddWithValue("@dnsServerIP", dnsServerIP);
                        sqlCmd.Parameters.AddWithValue("@dnsServerZone", dnsServerZone);
                        sqlCmd.Parameters.AddWithValue("@serialNumber", serialNumber);
                        sqlCmd.Parameters.AddWithValue("@issuerName", issuerName);
                        sqlCmd.Parameters.AddWithValue("@issuedTo", issuedTo);
                        sqlCmd.Parameters.AddWithValue("@subjectName", subjectName);
                        sqlCmd.Parameters.AddWithValue("@validFromSQLTime", validFromSQLTime);
                        sqlCmd.Parameters.AddWithValue("@expiresDateSQLTime", expiresDateSQLTime);
                        sqlCmd.Parameters.AddWithValue("@expiresDays", expiresDays);
                        sqlCmd.Parameters.AddWithValue("@signatureAlgorithm", signatureAlgorithm);
                        sqlCmd.Parameters.AddWithValue("@subjectAlternativeNames", subjectAlternativeNames);
                        connection.Open();
                        sqlCmd.ExecuteNonQuery();
                        connection.Close();
                    }
                }
            }
            catch (WebException)
            {
                // Skips expected exceptions
                // System.Net.WebException: The operation has timed out
                // System.Net.WebException: The remote server returned an error: (403) Forbidden.
                // System.Net.WebException: The remote server returned an error: (404) Not Found.
            }
            catch (Exception ex)
            {
                if (logLevel <= LogLevel.Warning)
                    WriteLog("WRN: ScanForCertificate(" + hostnameFQDN + "," + endpoint + "," + port + "," + dnsServerIP + "," + dnsServerZone + ") Exception: " + ex.ToString());
            }
        }
        private static bool AcceptAllCertifications(object sender, System.Security.Cryptography.X509Certificates.X509Certificate certification, System.Security.Cryptography.X509Certificates.X509Chain chain, System.Net.Security.SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }
        private static string GetDateTimeSQLString(DateTime SomeTime)
        {
            //yyyy-MM-dd HH:mm:ss
            string SqlTime = SomeTime.Year.ToString() + "-" + SomeTime.Month.ToString() + "-" + SomeTime.Day.ToString() + " " + SomeTime.Hour.ToString() + ":" + SomeTime.Minute + ":" + SomeTime.Second.ToString();
            return SqlTime;
        }
        public static void WriteLog(string logText)
        {
            try
            {
                string logTime = DateTime.Now.ToString("yyyy-MM-dd");
                string logFile = Globals.logFile.Replace("DATE", logTime);
                string outputText = logTime + DateTime.Now.ToString(" HH:mm:ss ") + logText;
#if !DEBUG
                if (!File.Exists(logFile))
                {
                    using (StreamWriter sw = File.CreateText(logFile))
                    {
                        sw.WriteLine(outputText);
                    }
                }
                else
                {
                    using (StreamWriter sw = File.AppendText(logFile))
                    {
                        sw.WriteLine(outputText);
                    }
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
