// Ignore Spelling: crypto

using Microsoft.CodeAnalysis.FlowAnalysis;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace WinCertDiagnosticTool
{
    public class ClientPSCertStoreManager
    {
        private Runspace _runspace;

        private X509Certificate2 x509Cert;

        public X509Certificate2 X509Cert
        {
            get { return x509Cert; }
        }

        public ClientPSCertStoreManager(Runspace runspace)
        {
            _runspace = runspace;
        }

        public string CreatePFXFile(string certificateContents, string privateKeyPassword)
        {
            try
            {
                using (PowerShell ps = PowerShell.Create())
                {
                    Console.WriteLine("Creating Runsapce");
                    ps.Runspace = _runspace;

                    // Add script to write certificate contents to a temporary file
                    string script = @"
                            param($certificateContents)
                            $filePath = [System.IO.Path]::GetTempFileName()
                            [System.IO.File]::WriteAllBytes($filePath, [System.Convert]::FromBase64String($certificateContents))
                            $filePath
                            ";

                    ps.AddScript(script);
                    ps.AddParameter("certificateContents", certificateContents); // Convert.ToBase64String(x509Cert.Export(X509ContentType.Pkcs12)));

                    // Invoke the script on the remote computer
                    var results = ps.Invoke();

                    // Get the result (temporary file path) returned by the script
                    return results[0].ToString();
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"An error occurred while attempting to create the certificate file. {ex.Message}");
            }
        }

        public bool ImportPFXFile(string filePath, string privateKeyPassword, string cryptoProviderName, string storePath)
        {
            try
            {
                using (PowerShell ps = PowerShell.Create())
                {
                    ps.Runspace = _runspace;

                    if (string.IsNullOrEmpty(cryptoProviderName))
                    {
                        if (string.IsNullOrEmpty(privateKeyPassword))
                        {
                            // If no private key password is provided, import the pfx file directory to the store using addstore argument
                            string script = @"
                            param($pfxFilePath, $storePath)
                            $output = certutil -f -addstore $storePath $pfxFilePath
                            $exit_message = ""LASTEXITCODE:$($LASTEXITCODE)""

                            if ($output.GetType().Name -eq ""String"")
                            {
                                $output = @($output, $exit_message)
                            }
                            else
                            {
                                $output += $exit_message
                            }
                            $output
                            ";

                            ps.AddScript(script);
                            ps.AddParameter("pfxFilePath", filePath);
                            ps.AddParameter("storePath", storePath);
                        }
                        else
                        {
                            // Use ImportPFX to import the pfx file with private key password to the appropriate cert store

                            string script = @"
                            param($pfxFilePath, $privateKeyPassword, $storePath)
                            $output = certutil -importpfx -p $privateKeyPassword $storePath $pfxFilePath 2>&1
                            $exit_message = ""LASTEXITCODE:$($LASTEXITCODE)""

                            if ($output.GetType().Name -eq ""String"")
                            {
                                $output = @($output, $exit_message)
                            }
                            else
                            {
                                $output += $exit_message
                            }
                            $output
                            ";

                            ps.AddScript(script);
                            ps.AddParameter("pfxFilePath", filePath);
                            ps.AddParameter("privateKeyPassword", privateKeyPassword);
                            ps.AddParameter("storePath", storePath);
                        }
                    }
                    else
                    {
                        if (string.IsNullOrEmpty(privateKeyPassword))
                        {
                            string script = @"
                            param($pfxFilePath, $cspName, $storePath)
                            $output = certutil -f -csp $cspName -addstore $storePath $pfxFilePath 2>&1
                            $exit_message = ""LASTEXITCODE:$($LASTEXITCODE)""

                            if ($output.GetType().Name -eq ""String"")
                            {
                                $output = @($output, $exit_message)
                            }
                            else
                            {
                                $output += $exit_message
                            }
                            $output
                            ";

                            ps.AddScript(script);
                            ps.AddParameter("pfxFilePath", filePath);
                            ps.AddParameter("cspName", cryptoProviderName);
                            ps.AddParameter("storePath", storePath);
                        }
                        else
                        {
                            string script = @"
                            param($pfxFilePath, $privateKeyPassword, $cspName)
                            $output = certutil -importpfx -csp $cspName -p $privateKeyPassword $storePath $pfxFilePath 2>&1
                            $exit_message = ""LASTEXITCODE:$($LASTEXITCODE)""

                            if ($output.GetType().Name -eq ""String"")
                            {
                                $output = @($output, $exit_message)
                            }
                            else
                            {
                                $output += $exit_message
                            }
                            $output
                            ";

                            ps.AddScript(script);
                            ps.AddParameter("pfxFilePath", filePath);
                            ps.AddParameter("privateKeyPassword", privateKeyPassword);
                            ps.AddParameter("cspName", cryptoProviderName);
                            ps.AddParameter("storePath", storePath);
                        }
                    }

                    // Invoke the script
                    var results = ps.Invoke();

                    // Get the last exist code returned from the script
                    int lastExitCode = 0;
                    try
                    {
                        lastExitCode = GetLastExitCode(results[^1].ToString());
                        Console.WriteLine($"Last exit code: {lastExitCode}");
                    }
                    catch (Exception)
                    {
                        Console.WriteLine("Unable to get the last exit code.");
                    }


                    bool isError = false;
                    if (lastExitCode != 0)
                    {
                        isError = true;
                        string outputMsg = "";

                        foreach (var result in results)
                        {
                            string outputLine = result.ToString();
                            if (!string.IsNullOrEmpty(outputLine))
                            {
                                outputMsg += "\n" + outputLine;
                            }
                        }
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine(outputMsg);
                        Console.ResetColor();
                    }
                    else
                    {
                        // Check for errors in the output
                        foreach (var result in results)
                        {
                            string outputLine = result.ToString();

                            Console.ForegroundColor = ConsoleColor.Yellow;
                            Console.WriteLine(outputLine);
                            Console.ResetColor();

                            if (!string.IsNullOrEmpty(outputLine) && outputLine.Contains("Error") || outputLine.Contains("permissions are needed"))
                            {
                                isError = true;
                                Console.ForegroundColor = ConsoleColor.Red;
                                Console.WriteLine(outputLine);
                                Console.ResetColor();
                            }
                        }
                    }

                    if (isError)
                    {
                        throw new Exception("Error occurred while attempting to import the pfx file.");
                    }
                    else
                    {
                        return true;
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error Occurred in ClientPSCertStoreManager.ImportPFXFile(): {e.Message}");
                return false;
            }
        }

        private int GetLastExitCode(string result)
        {
            // Split the string by colon
            string[] parts = result.Split(':');

            // Ensure the split result has the expected parts
            if (parts.Length == 2 && parts[0] == "LASTEXITCODE")
            {
                // Parse the second part into an integer
                if (int.TryParse(parts[1], out int lastExitCode))
                {
                    return lastExitCode;
                }
                else
                {
                    throw new Exception("Failed to parse the LASTEXITCODE value.");
                }
            }
            else
            {
                throw new Exception("The last element does not contain the expected format.");
            }
        }


        public bool AddCertificate(string certificateContents, string privateKeyPassword, string storePath, string certFileName = "")
        {
            try
            {
                using var ps = PowerShell.Create();

                ps.Runspace = _runspace;

                Console.WriteLine($"Creating X509 Cert from: {certFileName}");
                x509Cert = new X509Certificate2
                    (
                        Convert.FromBase64String(certificateContents),
                        privateKeyPassword,
                        X509KeyStorageFlags.MachineKeySet |
                        X509KeyStorageFlags.PersistKeySet |
                        X509KeyStorageFlags.Exportable
                    );
                X500DistinguishedName subjectName = x509Cert.SubjectName;
                Console.WriteLine($"X509 Cert Created With Subject: {subjectName.Name}");
                Console.WriteLine($"Begin Add for Cert Store {$@"\\{_runspace.ConnectionInfo.ComputerName}\{storePath}"}");

                // Add Certificate 
                var funcScript = @"
                        $ErrorActionPreference = ""Stop""

                        function InstallPfxToMachineStore([byte[]]$bytes, [string]$password, [string]$storeName) {
                            $certStore = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Store -ArgumentList $storeName, ""LocalMachine""
                            $certStore.Open(5)
                            $cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $bytes, $password, 18 <# Persist, Machine #>
                            $certStore.Add($cert)

                            $certStore.Close();
                        }";

                ps.AddScript(funcScript).AddStatement();

                ps.AddCommand("InstallPfxToMachineStore")
                    .AddParameter("bytes", Convert.FromBase64String(certificateContents))
                    .AddParameter("password", privateKeyPassword)
                    .AddParameter("storeName", $@"\\{_runspace.ConnectionInfo.ComputerName}\{storePath}");

                var results = ps.Invoke();
                
                if (ps.HadErrors)
                {
                    Console.WriteLine("ps Has Errors");
                    var psError = ps.Streams.Error.ReadAll()
                        .Aggregate(string.Empty, (current, error) => current + error?.ErrorDetails.Message);

                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine(psError);
                    Console.ResetColor();

                    return false;
                }

                ps.Commands.Clear();
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error attempting to add certificate: {e.Message}");
                return false;
            }
        }

    }
}
