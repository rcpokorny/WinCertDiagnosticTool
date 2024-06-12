using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace WinCertDiagnosticTool
{
    public class Certificate
    {
        public string Thumbprint { get; set; }
        public byte[] RawData { get; set; }
        public bool HasPrivateKey { get; set; }
        public string CertificateData => Convert.ToBase64String(RawData);
        public string CryptoServiceProvider { get; set; }
        public string SAN { get; set; }

        public class Utilities
        {
            public static string FormatSAN(string san)
            {
                // Use regular expression to extract key-value pairs
                var regex = new Regex(@"(?<key>DNS Name|Email|IP Address)=(?<value>[^=,\s]+)");
                var matches = regex.Matches(san);

                // Format matches into the desired format  
                string result = string.Join("&", matches.Cast<Match>()
                    .Select(m => $"{NormalizeKey(m.Groups["key"].Value)}={m.Groups["value"].Value}"));

                return result;
            }

            private static string NormalizeKey(string key)
            {
                return key.ToLower() switch
                {
                    "dns name" => "dns",
                    "email" => "email",
                    "ip address" => "ip",
                    _ => key.ToLower() // For other types, keep them as-is
                };
            }

        }
    }
}
