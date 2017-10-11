using ARSoft.Tools.Net;
using ARSoft.Tools.Net.Dns;
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

namespace CertificateScanner
{
    public class Globals
    {
        public static FileInfo appStartPath = new FileInfo(new Uri(Assembly.GetExecutingAssembly().CodeBase).LocalPath);
        public static string logLastRunFile = appStartPath.DirectoryName + @"\LogLastRun.txt";
        public static string logErrorsFile = appStartPath.DirectoryName + @"\LogErrors-DATE.txt";
        public static string sqlConnectionString = ""; // Read from .config
        public static bool hasErrorsCompleting = false;
    }

    class Program
    {
        [DllImport("dnsapi.dll", EntryPoint = "DnsFlushResolverCache")]
        private static extern UInt32 DnsFlushResolverCache();

        public static void FlushDNSCache()
        {
            uint result = DnsFlushResolverCache();
        }

        public enum trapStatus { Normal = 1, Warning = 2, Critical = 3 }

        static void Main(string[] args)
        {
            #region ### CONFIGURATION ###
            // Config
            string snmpServer = string.Empty;
            List<string> dnsServerZones = new List<string>();
            List<string> portsToScan = new List<string>();
            int maxErrorDaysThreshold = 0;
            int maxDaysThresholdWarning = 0;
            int maxDaysThresholdCritical = 0;
            try
            {
                Configuration configManager = ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None);
                KeyValueConfigurationCollection confCollection = configManager.AppSettings.Settings;
                portsToScan = ConfigurationManager.AppSettings["Ports"].Split(',').ToList();
                snmpServer = ConfigurationManager.AppSettings["SNMPServer"];
                Globals.sqlConnectionString = ConfigurationManager.AppSettings["SQLConnectionString"];
                maxErrorDaysThreshold = int.Parse(ConfigurationManager.AppSettings["MaxErrorDaysThreshold"]);
                maxDaysThresholdWarning = int.Parse(ConfigurationManager.AppSettings["MaxDaysThresholdWarning"]);
                maxDaysThresholdCritical = int.Parse(ConfigurationManager.AppSettings["MaxDaysThresholdCritical"]);

                foreach (string key in ConfigurationManager.AppSettings)
                {
                    if (key.ToLower().StartsWith("dnsserverzone"))
                        dnsServerZones.Add(ConfigurationManager.AppSettings[key]);
                }
            }
            catch (Exception ex)
            {
                WriteLog("ERR: Main() failed to read configuration Exception: " + ex.ToString());
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
                    SendTrap(snmpServer, trapStatus.Critical, "Certificate scanner has not completed a certificate scan for over " + maxErrorDaysThreshold.ToString() + " days, check error logs!");
                    Globals.hasErrorsCompleting = true; // Set so we dont overwrite snmp status unless we are able to successfully complete
                }
            }
            else
                File.WriteAllText(Globals.logLastRunFile, DateTime.Now.ToString()); // Create initial log file
            #endregion
#if !DEBUG
            #region ### WORK - GET DNS RECORDS AND SCAN ###
            foreach (string dnsServerZone in dnsServerZones)
            {
                FlushDNSCache(); // Flush dns cache

                string dnsServerIP = dnsServerZone.Split(';')[0];
                string dnsZone = dnsServerZone.Split(';')[1];

                DataTable dtDNSrecs = new DataTable();
                dtDNSrecs.Columns.Add("hostnameFQDN");
                dtDNSrecs.Columns.Add("endpoint");
                dtDNSrecs.Columns.Add("dnsServerIP");
                dtDNSrecs.Columns.Add("dnsZone");

                DnsClient dnsCli = new DnsClient(IPAddress.Parse(dnsServerIP), 60000); // DNSServer to query and ms timeout value
                DnsMessage dnsMessage = dnsCli.Resolve(DomainName.Parse(dnsZone), RecordType.Axfr); // Zone transfer query
                if ((dnsMessage == null) || ((dnsMessage.ReturnCode != ReturnCode.NoError) && (dnsMessage.ReturnCode != ReturnCode.NxDomain)))
                {
                    WriteLog("ERR: Main() DNS zone request failed on server " + dnsServerIP + " zone " + dnsZone);
                }
                else
                {
                    foreach (DnsRecordBase dnsRecord in dnsMessage.AnswerRecords)
                    {
                        if (dnsRecord.RecordType == RecordType.A)
                        {
                            ARecord aRecord = dnsRecord as ARecord;
                            if (aRecord != null)
                            {
                                // Optionally: Skip known entries, eg. dynamically updated computer pc objects
                                //if (aRecord.Name.ToString().StartsWith("MININT") || aRecord.Name.ToString().StartsWith("SVG-"))
                                //    continue;
                                DataRow newRow = dtDNSrecs.NewRow();
                                newRow["hostnameFQDN"] = aRecord.Name;
                                newRow["endpoint"] = aRecord.Address;
                                newRow["dnsServerIP"] = dnsServerIP;
                                newRow["dnsZone"] = dnsZone;
                                dtDNSrecs.Rows.Add(newRow);
                            }
                        }
                        else if (dnsRecord.RecordType == RecordType.CName)
                        {
                            CNameRecord cnameRecord = dnsRecord as CNameRecord;
                            if (cnameRecord != null)
                            {
                                DataRow newRow = dtDNSrecs.NewRow();
                                newRow["hostnameFQDN"] = cnameRecord.Name;
                                newRow["endpoint"] = cnameRecord.CanonicalName;
                                newRow["dnsServerIP"] = dnsServerIP;
                                newRow["dnsZone"] = dnsZone;
                                dtDNSrecs.Rows.Add(newRow);
                            }
                        }
                    }
                }
                
                // Scan all A and CNAME records on known ports for certificates
                foreach (string port in portsToScan)
                {
                    foreach (DataRow row in dtDNSrecs.Rows)
                    {
                        string hostnameFQDN = row["hostnameFQDN"].ToString();
                        if (hostnameFQDN.EndsWith("."))
                            hostnameFQDN = hostnameFQDN.Remove(hostnameFQDN.Length - 1);
                        string endpoint = row["endpoint"].ToString();
                        if (endpoint.EndsWith("."))
                            endpoint = endpoint.Remove(endpoint.Length - 1);
                        ScanForCertificate(hostnameFQDN, endpoint, port, dnsServerIP, dnsZone);
                    }
                }
            }
            File.WriteAllText(Globals.logLastRunFile, DateTime.Now.ToString()); // Log updated successful run datetime
            #endregion
#endif
            #region ### CHECK CERTIFICATES FOUND AND UPDATE TRAP STATUS ###
            StringBuilder sb = new StringBuilder();
            DataTable dtAllCerts = GetSQLCertificates();
            DataView dvCertificates = new DataView(dtAllCerts);

            dvCertificates.Sort = "expiresDays ASC";
            dvCertificates.RowFilter = "expiresDays <= " + maxDaysThresholdCritical.ToString();

            if (dvCertificates.Count > 0) // Send trap for critical
            {
                sb.Append("EXPIRING (DAYS:DOMAINNAME:ENDPOINT) ");
                foreach (DataRowView drv in dvCertificates)
                {
                    sb.Append("(" + drv["expiresDays"] + ":" + drv["hostnameFQDN"] + ":" + drv["endpoint"] + ")");
                }
                SendTrap(snmpServer, trapStatus.Critical, sb.ToString());
            }
            else
            {
                dvCertificates.RowFilter = "expiresDays <= " + maxDaysThresholdWarning.ToString();
                if (dvCertificates.Count > 0) // Check for warning
                {
                    sb.Append("EXPIRING (DAYS:DOMAINNAME:ENDPOINT) ");
                    foreach (DataRowView drv in dvCertificates)
                    {
                        sb.Append("(" + drv["expiresDays"] + ":" + drv["hostnameFQDN"] + ":" + drv["endpoint"] + ")");
                    }
                    SendTrap(snmpServer, trapStatus.Warning, sb.ToString());
                }
            }
            // No warning, critical or errors => send OK
            if (dvCertificates.Count == 0 && !Globals.hasErrorsCompleting)
            {
                sb.Append("OK. No certificates found expiring in the next " + maxDaysThresholdWarning.ToString() + " days.");
                SendTrap(snmpServer, trapStatus.Normal, sb.ToString());
            }
            #endregion
        }

        public static void SendTrap(string serverIp, trapStatus status, string message)
        {
            try
            {
                int intStatus = (int)status;
                ObjectIdentifier oID = new ObjectIdentifier("2.25.999." + intStatus.ToString());
                IPEndPoint ipManager = new IPEndPoint(IPAddress.Parse(serverIp), 162);
                List<Variable> SNMPVariables = new List<Variable>();
                Variable var1 = new Variable(oID, new OctetString(message));
                SNMPVariables.Add(var1);
                Messenger.SendTrapV2(0, VersionCode.V2, ipManager, new OctetString("public"), oID, 0, SNMPVariables);
            }
            catch (Exception ex)
            {
                WriteLog("ERR: SendTrap() Exception: " + ex.ToString());
            }
        }
        public static DataTable GetSQLCertificates()
        {
            DataTable dt = new DataTable();
            try
            {
                using (SqlConnection connection = new SqlConnection(Globals.sqlConnectionString))
                {
                    SqlDataAdapter da = new SqlDataAdapter("SELECT  hostnameFQDN, endpoint, expiresDays " +
                                                           "FROM            certificatesLog " +
                                                           "WHERE lastScannedDate > '" + GetDateTimeSQLString(DateTime.Now.AddDays(-1)) + "'", connection);
                    da.Fill(dt);
                }
            }
            catch (Exception ex)
            {
                WriteLog("ERR: GetSQLCertificates() Exception: " + ex.ToString());
            }
            return dt;
        }
        private static void ScanForCertificate(string hostnameFQDN, string endpoint, string portNumber, string dnsServerIP, string dnsServerZone)
        {

            try
            {
                // Ignore SSL errors
                ServicePointManager.ServerCertificateValidationCallback = new System.Net.Security.RemoteCertificateValidationCallback(AcceptAllCertifications);

                var ipUri = new UriBuilder(Uri.UriSchemeHttps, endpoint, int.Parse(portNumber)).Uri;
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(ipUri);
                request.Host = hostnameFQDN;

                request.AllowAutoRedirect = false;
                request.Timeout = 5000; // 5s timeout

                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                response.Close();

                // Getretrieve the ssl cert and assign it to an X509Certificate object
                X509Certificate cert = request.ServicePoint.Certificate;

                //convert the X509Certificate to an X509Certificate2 object by passing it into the constructor
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

                // Check if certificate already exists in sql. Match on (hostnameFQDN && endpoint && serialnumber) to also identifiy split dns and server name indication scenarios
                using (SqlConnection connection = new SqlConnection(Globals.sqlConnectionString))
                {
                    string sqlGetCertificateInfo = "SELECT COUNT(*) AS Expr1 FROM certificatesLog WHERE (hostnameFQDN = N'" + hostnameFQDN + "') AND (endpoint = N'" + endpoint + "') AND (serialNumber = N'" + serialNumber + "')";
                    SqlCommand sqlCmd = new SqlCommand(sqlGetCertificateInfo, connection);
                    connection.Open();
                    int result = (int)sqlCmd.ExecuteScalar();
                    if (result > 0)
                    {
                        alreadyRegisteredInSQL = true;
                        // Update LastScanned record in database
                        string sqlUpdateCertificateInfoLastScanned = "UPDATE certificatesLog SET lastScannedDate = { fn NOW() }, expiresDays = @expiresDays, subjectAlternativeNames = @subjectAlternativeNames  WHERE (hostnameFQDN = @hostnameFQDN) AND (endpoint = @endpoint) AND (serialNumber = @serialNumber)";
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
                        string sqlInsertCertificateInfo = "INSERT INTO certificatesLog " +
                            "(hostnameFQDN, endpoint, port, dnsServerIP, dnsServerZone, serialNumber, issuerName, issuedTo, subjectName, validFromDate, expiresDate, expiresDays, signatureAlgorithm, subjectAlternativeNames) VALUES " +
                            "(@hostnameFQDN, @endpoint, @targetPort, @dnsServerIP, @dnsServerZone, @serialNumber, @issuerName, @issuedTo , @subjectName, @validFromSQLTime, @expiresDateSQLTime, @expiresDays, @signatureAlgorithm, @subjectAlternativeNames)";
                        SqlCommand sqlCmd = new SqlCommand(sqlInsertCertificateInfo, connection);
                        sqlCmd.Parameters.AddWithValue("@hostnameFQDN", hostnameFQDN);
                        sqlCmd.Parameters.AddWithValue("@endpoint", endpoint);
                        sqlCmd.Parameters.AddWithValue("@targetPort", portNumber);
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
                WriteLog("ERR: ScanForCertificate(" + hostnameFQDN + "," + endpoint + "," + portNumber + "," + dnsServerIP + "," + dnsServerZone + ") Exception: " + ex.ToString());
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
                string logFile = Globals.logErrorsFile.Replace("DATE", logTime);
                string outputText = logTime + DateTime.Now.ToString(" HH:mm:ss ") + logText;
#if !DEBUG
                if (!System.IO.File.Exists(logFile))
                {
                    using (System.IO.StreamWriter sw = System.IO.File.CreateText(logFile))
                    {
                        sw.WriteLine(outputText);
                    }
                }
                else
                {
                    using (System.IO.StreamWriter sw = System.IO.File.AppendText(logFile))
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
