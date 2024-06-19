using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation.Runspaces;
using System.Management.Automation;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;

namespace WinCertDiagnosticTool
{
    internal class ClientPSIISManager
    {
        private string SiteName { get; set; }
        private string Port { get; set; }
        private string Protocol { get; set; }
        private string HostName { get; set; }
        private string SniFlag { get; set; }
        private string IPAddress { get; set; }
        
        private string StorePath { get; set; }
        private string ClientMachineName { get; set; }
        private readonly Runspace _runSpace;
        
        private string CertContents { get; set; } = "";
        private string PrivateKeyPassword { get; set; } = "";
        private string RenewalThumbprint { get; set; } = "";

        private PowerShell ps;

        public ClientPSIISManager(IISConfiguration config, string serverUsername, string serverPassword, string winRMProtocol, string clientMachineName, string winRMPort, bool includePortInSPN, string storePath)
        {
            try
            {
                SiteName = config.SiteName;
                Port = config.Port;
                Protocol = config.Protocol;
                HostName = config.HostName;
                SniFlag = config.SniFlag;
                IPAddress = config.IPAddress;

                PrivateKeyPassword = "";
                RenewalThumbprint = "";
                CertContents = "";

                ClientMachineName = clientMachineName;
                StorePath = storePath;

                _runSpace = PSHelper.GetClientPsRunspace(ClientMachineName, winRMProtocol, winRMPort, includePortInSPN, serverUsername, serverPassword);

            }
            catch (Exception e)
            {
                Console.WriteLine($"Error when initiating an IIS Management Job: {e.Message}");
            }

        }

        public bool BindCertificate(X509Certificate2 x509Cert)
        {
            try
            {
                _runSpace.Open();
                ps = PowerShell.Create();
                ps.Runspace = _runSpace;

                //if thumbprint is there it is a renewal so we have to search all the sites for that thumbprint and renew them all
                if (RenewalThumbprint?.Length > 0)
                {
                    ps.AddCommand("Import-Module")
                        .AddParameter("Name", "WebAdministration")
                        .AddStatement();

                    var searchScript =
                        "Foreach($Site in get-website) { Foreach ($Bind in $Site.bindings.collection) {[pscustomobject]@{name=$Site.name;Protocol=$Bind.Protocol;Bindings=$Bind.BindingInformation;thumbprint=$Bind.certificateHash;sniFlg=$Bind.sslFlags}}}";
                    ps.AddScript(searchScript).AddStatement();
                    var bindings = ps.Invoke();

                    foreach (var binding in bindings)
                    {
                        if (binding.Properties["Protocol"].Value.ToString().Contains("https"))
                        {
                            var bindingSiteName = binding.Properties["name"].Value.ToString();
                            var bindingBindings = binding.Properties["Bindings"].Value.ToString()?.Split(':');
                            var bindingIpAddress = bindingBindings?.Length > 0 ? bindingBindings[0] : null;
                            var bindingPort = bindingBindings?.Length > 1 ? bindingBindings[1] : null;
                            var bindingHostName = bindingBindings?.Length > 2 ? bindingBindings[2] : null;
                            var bindingProtocol = binding.Properties["Protocol"]?.Value?.ToString();
                            var bindingThumbprint = binding.Properties["thumbprint"]?.Value?.ToString();
                            var bindingSniFlg = binding.Properties["sniFlg"]?.Value?.ToString();

                            Console.WriteLine($"bindingSiteName: {bindingSiteName}, bindingIpAddress: {bindingIpAddress}, bindingPort: {bindingPort}, bindingHostName: {bindingHostName}, bindingProtocol: {bindingProtocol}, bindingThumbprint: {bindingThumbprint}, bindingSniFlg: {bindingSniFlg}");

                            //if the thumbprint of the renewal request matches the thumbprint of the cert in IIS, then renew it
                            if (RenewalThumbprint == bindingThumbprint)
                            {
                                Console.WriteLine($"Thumbprint Match {RenewalThumbprint}={bindingThumbprint}");

                                var funcScript = string.Format(@"
                                            $ErrorActionPreference = ""Stop""

                                            $IISInstalled = Get-Module -ListAvailable | where {{$_.Name -eq ""WebAdministration""}}
                                            if($IISInstalled) {{
                                                Import-Module WebAdministration
                                                Get-WebBinding -Name ""{0}"" -IPAddress ""{1}"" -HostHeader ""{4}"" -Port ""{2}"" -Protocol ""{3}"" |
                                                    ForEach-Object {{ Remove-WebBinding -BindingInformation  $_.bindingInformation }}

                                                New-WebBinding -Name ""{0}"" -IPAddress ""{1}"" -HostHeader ""{4}"" -Port ""{2}"" -Protocol ""{3}"" -SslFlags ""{7}""
                                                Get-WebBinding -Name ""{0}"" -IPAddress ""{1}"" -HostHeader ""{4}"" -Port ""{2}"" -Protocol ""{3}"" | 
                                                    ForEach-Object {{ $_.AddSslCertificate(""{5}"", ""{6}"") }}
                                            }}", 
                                    bindingSiteName, //{0} 
                                    bindingIpAddress, //{1}
                                    bindingPort, //{2}
                                    bindingProtocol, //{3}
                                    bindingHostName, //{4}
                                    x509Cert.Thumbprint, //{5} 
                                    StorePath, //{6}
                                    bindingSniFlg); //{7}

                                //_logger.LogTrace($"funcScript {funcScript}");
                                ps.AddScript(funcScript);
                                //_logger.LogTrace("funcScript added...");
                                ps.Invoke();
                                //_logger.LogTrace("funcScript Invoked...");
                                ps.Commands.Clear();
                                //_logger.LogTrace("Commands Cleared..");
                            }
                        }
                    }
                }
                else
                {
                    var funcScript = string.Format(@"
                                            $ErrorActionPreference = ""Stop""

                                            $IISInstalled = Get-Module -ListAvailable | where {{$_.Name -eq ""WebAdministration""}}
                                            if($IISInstalled) {{
                                                Import-Module WebAdministration
                                                Get-WebBinding -Name ""{0}"" -IPAddress ""{1}"" -Port ""{2}"" -Protocol ""{3}"" -HostHeader ""{4}"" |
                                                    ForEach-Object {{ Remove-WebBinding -BindingInformation  $_.bindingInformation }}

                                                New-WebBinding -Name ""{0}"" -IPAddress ""{1}"" -HostHeader ""{4}"" -Port ""{2}"" -Protocol ""{3}"" -SslFlags ""{7}""
                                                Get-WebBinding -Name ""{0}"" -IPAddress ""{1}"" -HostHeader ""{4}"" -Port ""{2}"" -Protocol ""{3}"" | 
                                                    ForEach-Object {{ $_.AddSslCertificate(""{5}"", ""{6}"") }}
                                            }}", 
                        SiteName, //{0} 
                        IPAddress, //{1}
                        Port, //{2}
                        Protocol, //{3}
                        HostName, //{4}
                        x509Cert.Thumbprint, //{5} 
                        StorePath, //{6}
                        Convert.ToInt16(SniFlag)); //{7}

                    //foreach (var cmd in ps.Commands.Commands)
                    //{
                    //    _logger.LogTrace("Logging PowerShell Command");
                    //    _logger.LogTrace(cmd.CommandText);
                    //}

                    //_logger.LogTrace($"funcScript {funcScript}");
                    ps.AddScript(funcScript);
                    //_logger.LogTrace("funcScript added...");
                    ps.Invoke();
                    //_logger.LogTrace("funcScript Invoked...");
                }

                if (ps.HadErrors)
                {
                    var psError = ps.Streams.Error.ReadAll()
                        .Aggregate(string.Empty, (current, error) => current + error.ErrorDetails.Message);

                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine(psError);
                    Console.ResetColor();

                    return false;
                }
                return true;
            }
            catch (Exception e)
            {

                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(e.Message);
                Console.ResetColor();

                return false;
            }
            finally
            {
                _runSpace.Close();
                ps.Runspace.Close();
                ps.Dispose();
            }
        }
    }
}
