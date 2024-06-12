using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation.Runspaces;
using System.Management.Automation;
using System.Text;
using System.Threading.Tasks;

namespace WinCertDiagnosticTool
{
    public static class ClientPSCertStoreInventory
    {
        public static List<Certificate> GetCertificatesFromStore(Runspace runSpace, string storePath)
        {
            List<Certificate> myCertificates = new List<Certificate>();
            try
            {
                using var ps = PowerShell.Create();

                ps.Runspace = runSpace;

                var certStoreScript = $@"
                                $certStore = New-Object System.Security.Cryptography.X509Certificates.X509Store('{storePath}','LocalMachine')
                                $certStore.Open('ReadOnly')
                                $certs = $certStore.Certificates
                                $certStore.Close()
                                $certStore.Dispose()
                                    $certs | ForEach-Object {{
                                        $certDetails = @{{
                                            Subject = $_.Subject
                                            Thumbprint = $_.Thumbprint
                                            HasPrivateKey = $_.HasPrivateKey
                                            RawData = $_.RawData
                                            san = $_.Extensions | Where-Object {{ $_.Oid.FriendlyName -eq ""Subject Alternative Name"" }} | ForEach-Object {{ $_.Format($false) }}
                                        }}

                                        if ($_.HasPrivateKey) {{
                                            $certDetails.CSP = $_.PrivateKey.CspKeyContainerInfo.ProviderName
                                        }}

                                        New-Object PSObject -Property $certDetails
                                }}";

                ps.AddScript(certStoreScript);

                var certs = ps.Invoke();

                foreach (var c in certs)
                {
                    myCertificates.Add(new Certificate
                    {
                        Thumbprint = $"{c.Properties["Thumbprint"]?.Value}",
                        HasPrivateKey = bool.Parse($"{c.Properties["HasPrivateKey"]?.Value}"),
                        RawData = (byte[])c.Properties["RawData"]?.Value,
                        CryptoServiceProvider = $"{c.Properties["CSP"]?.Value}",
                        SAN = Certificate.Utilities.FormatSAN($"{c.Properties["san"]?.Value}")
                    });
                }

                return myCertificates;
            }
            catch (Exception ex)
            {
                throw new Exception(
                    $"Error listing certificate in {storePath} store on {runSpace.ConnectionInfo.ComputerName}: {ex.Message}");
            }
        }
    }
}
