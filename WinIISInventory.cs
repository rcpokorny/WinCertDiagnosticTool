using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation.Runspaces;
using System.Management.Automation;
using System.Text;
using System.Threading.Tasks;

namespace WinCertDiagnosticTool
{
    internal class WinIISInventory : ClientPSCertStoreInventory
    {
        public List<CurrentInventoryItem> GetInventoryItems(Runspace runSpace, string storePath)
        {
            // Get the raw certificate inventory from cert store
            List<Certificate> certificates = base.GetCertificatesFromStore(runSpace, storePath);

            Console.WriteLine($"A total of {certificates.Count} certificates were found in cert store {storePath}.  Checking for bindings.");

            // Contains the inventory items to be sent back to KF
            List<CurrentInventoryItem> myBoundCerts = new List<CurrentInventoryItem>();

            using (PowerShell ps2 = PowerShell.Create())
            {
                ps2.Runspace = runSpace;

                if (runSpace.RunspaceIsRemote)
                {
                    ps2.AddCommand("Import-Module")
                        .AddParameter("Name", "WebAdministration")
                        .AddStatement();
                }
                else
                {
                    ps2.AddScript("Set-ExecutionPolicy RemoteSigned");
                    ps2.AddScript("Import-Module WebAdministration");
                    //var result = ps.Invoke();
                }

                var searchScript = "Foreach($Site in get-website) { Foreach ($Bind in $Site.bindings.collection) {[pscustomobject]@{name=$Site.name;Protocol=$Bind.Protocol;Bindings=$Bind.BindingInformation;thumbprint=$Bind.certificateHash;sniFlg=$Bind.sslFlags}}}";
                ps2.AddScript(searchScript);
                var iisBindings = ps2.Invoke();  // Responsible for getting all bound certificates for each website

                if (ps2.HadErrors)
                {
                    string psError = string.Empty;
                    try
                    {
                        psError = ps2.Streams.Error.ReadAll().Aggregate(String.Empty, (current, error) => current + (error.ErrorDetails?.Message ?? error.Exception.ToString()));
                    }
                    catch
                    {
                    }

                    if (psError != null) { throw new Exception(psError); }

                }

                if (iisBindings.Count == 0)
                {
                    Console.WriteLine("No binding certificates were found.");
                    return myBoundCerts;
                }

                //in theory should only be one, but keeping for future update to chance inventory
                foreach (var binding in iisBindings)
                {
                    var thumbPrint = $"{(binding.Properties["thumbprint"]?.Value)}";
                    if (string.IsNullOrEmpty(thumbPrint)) continue;

                    Certificate foundCert = certificates.Find(m => m.Thumbprint.Equals(thumbPrint));

                    if (foundCert == null) continue;

                    var sniValue = "";
                    switch (Convert.ToInt16(binding.Properties["sniFlg"]?.Value))
                    {
                        case 0:
                            sniValue = "0 - No SNI";
                            break;
                        case 1:
                            sniValue = "1 - SNI Enabled";
                            break;
                        case 2:
                            sniValue = "2 - Non SNI Binding";
                            break;
                        case 3:
                            sniValue = "3 - SNI Binding";
                            break;
                    }

                    var siteSettingsDict = new Dictionary<string, object>
                             {
                                 { "SiteName", binding.Properties["Name"]?.Value },
                                 { "Port", binding.Properties["Bindings"]?.Value.ToString()?.Split(':')[1] },
                                 { "IPAddress", binding.Properties["Bindings"]?.Value.ToString()?.Split(':')[0] },
                                 { "HostName", binding.Properties["Bindings"]?.Value.ToString()?.Split(':')[2] },
                                 { "SniFlag", sniValue },
                                 { "Protocol", binding.Properties["Protocol"]?.Value },
                                 { "ProviderName", foundCert.CryptoServiceProvider },
                                 { "SAN", foundCert.SAN }
                             };

                    myBoundCerts.Add(
                        new CurrentInventoryItem
                        {
                            Certificates = new[] { foundCert.CertificateData },
                            Alias = thumbPrint,
                            PrivateKeyEntry = foundCert.HasPrivateKey,
                            UseChainLevel = false,
                            ItemStatus = OrchestratorInventoryItemStatus.Unknown,
                            Parameters = siteSettingsDict
                        }
                    );
                }
            }

            return myBoundCerts;
        }
    }
}
