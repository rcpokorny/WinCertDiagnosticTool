using System.Management;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Net.NetworkInformation;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.ServiceProcess;

namespace WinCertDiagnosticTool
{
    internal class Program
    {
        static void Main(string[] args)
        {
            // Define default values
            string defaultProtocol = "http";
            string defaultMachineOrIp = string.Empty;
            string defaultPort = "5985";
            string defaultStore = "My";

            string certPath = "";
            string certPassword = "";
            bool hasPrivateKey = false;

            string certificateContents = "";

            Runspace rs;

            while (true)
            {
                Console.Clear();

                string protocol = "";
                string port = "";
                string username = "";
                string password = "";

                // Ask for connection details
                string getInventory = PromptForInput("Get Inventory only (Y/N): ", "y");
                   
                string machineOrIp = PromptForInput("Client machine or IP address: ", defaultMachineOrIp);
                if (machineOrIp.ToLower() != "localhost" && machineOrIp.ToLower() != "localmachine")
                {
                    protocol = PromptForInput("Protocol (http/https): ", defaultProtocol);
                    port = PromptForInput("Port number: ", defaultPort);
                    username = PromptForInput("Username: ", "");
                    password = PromptForPassword("Password: ", "");
                }

                // Ask for certificate details
                while (true)
                {
                    certPath = PromptForInput("Path and filename of certificate file: ", "");

                    if (string.IsNullOrEmpty(certPath))
                    {
                        break;
                    }
                    else
                    {

                        if (!File.Exists(certPath))
                        {
                            Console.WriteLine($"File: {certPath} was not found.  Please check the filename again.");
                        }
                        else
                        {

                            certPassword = "";
                            bool correctPassword = false;

                            while (!correctPassword)
                            {
                                try
                                {
                                    // Determine whether the pfx contains a private key.  If so, ask for the password
                                    X509Certificate2 cert = new X509Certificate2(certPath);
                                    hasPrivateKey = cert.HasPrivateKey;
                                    correctPassword = true;
                                }
                                catch (CryptographicException)
                                {
                                    // Must be password protected
                                    try
                                    {
                                        certPassword = PromptForPassword($"Enter Password for {certPath}:", "");
                                        X509Certificate2 cert = new X509Certificate2(certPath, certPassword);
                                        hasPrivateKey = cert.HasPrivateKey;
                                        correctPassword = true;
                                    }
                                    catch (Exception ex)
                                    {
                                        Console.WriteLine(ex.Message);
                                    }
                                }
                            }


                            // Got the correct PFX, password; turn it into Base64 to be sent to the remote host
                            byte[] fileBytes = File.ReadAllBytes(certPath);
                            certificateContents = Convert.ToBase64String(fileBytes);
                            break;
                        }
                    }
                }

                string storeName = PromptForInput("Store name to add the certificate to (e.g., My, Root, etc.): ", defaultStore);

                Console.WriteLine();
                Console.WriteLine();

                // Perform some checks
                if (!CheckLocalWinRM())
                {
                    Console.WriteLine("WinRM is not enabled or running on the local machine.");
                }

                try
                {
                    Console.WriteLine("Attempting to connect to remote host and establish PowerShell Runspace.");
                    rs = PSHelper.GetClientPsRunspace(protocol, machineOrIp, port, false, username, password);
                    Console.WriteLine("The remote runspace has been created.");
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                    Console.WriteLine();
                    Console.WriteLine();

                    // Prompt to continue or exit
                    Console.Write("Type 'exit' to end the application or press Enter to continue: ");
                    string? input2 = Console.ReadLine();
                    if (input2?.Trim().ToLower() == "exit")
                    {
                        break;
                    }

                    continue;
                }

                try
                {
                    rs.Open();
                    Console.WriteLine("Runspace opened.");

                    if (getInventory.ToLower() == "y")
                    {
                        Console.WriteLine("Attempting to Get the inventory on the remote computer.");
                        List<CurrentInventoryItem> items = WinIISInventory.GetInventoryItems(rs, storeName);
                        Console.WriteLine($"A total of {items.Count} bound certificates were found.");
                        Console.WriteLine();
                    }
                    else
                    {
                        if (!string.IsNullOrEmpty(certPath))
                        {
                            ClientPSCertStoreManager manager = new ClientPSCertStoreManager(rs);

                            // Create certificate file on remote computer
                            Console.WriteLine("Attempting to create the certificate file on the remote computer.");
                            string remoteFilePath = manager.CreatePFXFile(certificateContents, certPassword);
                            Console.WriteLine($"Created certificate file on remote host {remoteFilePath}");

                            // Import into cert store
                            Console.WriteLine($"Attempting to import the certificate into the {storeName} store.");
                            if (manager.ImportPFXFile(remoteFilePath, certPassword, "", storeName))
                            {
                                Console.ForegroundColor = ConsoleColor.Green;
                                Console.WriteLine("The import completed successfully.  Review previous messages for results.");
                                Console.ResetColor();
                            }
                            else
                            {
                                Console.ForegroundColor = ConsoleColor.Red;
                                Console.WriteLine("Import was NOT successful!");
                                Console.ResetColor();
                            }
                        }
                        else Console.WriteLine("No filename was selected.");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                }
                finally
                {
                    rs.Close();
                    Console.WriteLine("Runspace closed.");
                }

                // Update default values with the current inputs
                defaultProtocol = protocol;
                defaultMachineOrIp = machineOrIp;
                defaultPort = port;
                defaultStore = storeName;

                // Prompt to continue or exit
                Console.WriteLine();
                Console.Write("Type 'exit' to end the application or press Enter to continue: ");
                string? input = Console.ReadLine();
                if (input?.Trim().ToLower() == "exit")
                {
                    break;
                }
            }
        }

        #if WINDOWS
        static bool CheckLocalWinRM()
        {
            try
            {
#pragma warning disable CA1416 // Validate platform compatibility
                ServiceController sc = new("WinRM");
                if (sc.Status == ServiceControllerStatus.Running)
                {
                    Console.WriteLine("WinRM is running on the local machine.");
                    return true;
                }
                else
                {
                    Console.WriteLine("WinRM is not running on the local machine.  Please verify the WinRM service is able to start.");
                    return false;
                }
#pragma warning restore CA1416 // Validate platform compatibility
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error checking WinRM on the local machine: {ex.Message}");
                return false;
            }
        }
        #endif

        static bool CheckRemoteConnectivity(string address)
        {
            try
            {
                Ping ping = new Ping();
                PingReply reply = ping.Send(address);

                if (reply.Status == IPStatus.Success)
                {
                    Console.WriteLine("Remote machine is reachable.");
                    return true;
                }
                else
                {
                    Console.WriteLine($"Ping failed with status: {reply.Status}");
                    return false;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error pinging remote machine: {ex.Message}");
                return false;
            }
        }

        static string ReadPassword()
        {
            string password = string.Empty;
            ConsoleKeyInfo key;

            do
            {
                key = Console.ReadKey(true);

                if (key.Key != ConsoleKey.Backspace && key.Key != ConsoleKey.Enter)
                {
                    password += key.KeyChar;
                    Console.Write("*");
                }
                else if (key.Key == ConsoleKey.Backspace && password.Length > 0)
                {
                    password = password[0..^1];
                    Console.Write("\b \b");
                }
            } while (key.Key != ConsoleKey.Enter);

            Console.WriteLine();
            return password;
        }

        static string PromptForInput(string prompt, string defaultValue)
        {
            if(string.IsNullOrEmpty(defaultValue))
            {
                Console.Write(prompt + ": ");
            }
            else Console.Write(prompt + $"[{defaultValue}]: ");

            string? input = Console.ReadLine();
            return string.IsNullOrWhiteSpace(input) ? defaultValue : input;
        }

        static string PromptForPassword(string prompt, string defaultValue)
        {
            if (string.IsNullOrEmpty(defaultValue))
            {
                Console.Write(prompt + ": ");
            }
            else Console.Write(prompt + $"[{defaultValue}]: ");

            string input = ReadPassword();
            return string.IsNullOrWhiteSpace(input) ? defaultValue : input;
        }

        static void GetCertificates(string connectionUri, string username, string password)
        {
            // Create a secure password
            var securePassword = new System.Security.SecureString();
            foreach (char c in password)
            {
                securePassword.AppendChar(c);
            }

            // Create the PSCredential object
            var credentials = new PSCredential(username, securePassword);

            // Create the WSManConnectionInfo object
            var connectionInfo = new WSManConnectionInfo(new Uri(connectionUri), "http://schemas.microsoft.com/powershell/Microsoft.PowerShell", credentials)
            {
                SkipCACheck = true,
                SkipCNCheck = true,
                SkipRevocationCheck = true
            };

            using (var runspace = RunspaceFactory.CreateRunspace(connectionInfo))
            {
                runspace.Open();

                using (var pipeline = runspace.CreatePipeline())
                {
                    // Add the command to get the certificates
                    pipeline.Commands.AddScript("Get-ChildItem -Path Cert:\\LocalMachine\\My");

                    try
                    {
                        // Execute the command and get the results
                        var results = pipeline.Invoke();

                        // Display the certificates
                        foreach (var result in results)
                        {
                            try
                            {
                                Console.WriteLine($"Result: {result.ToString()}");
                            }
                            catch (Exception)
                            {
                            }

                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"An error occurred: {ex.Message}");
                    }
                }
            }
        }

        static void AddCertificate(string connectionUri, string username, string password, string certPath, string certPassword, string storeName)
        {
            try
            {
                // Create a secure password
                var securePassword = new SecureString();
                foreach (char c in password)
                {
                    securePassword.AppendChar(c);
                }

                // Create the PSCredential object
                var credentials = new PSCredential(username, securePassword);

                // Create the WSManConnectionInfo object
                var connectionInfo = new WSManConnectionInfo(new Uri(connectionUri), "http://schemas.microsoft.com/powershell/Microsoft.PowerShell", credentials)
                {
                    SkipCACheck = true,
                    SkipCNCheck = true,
                    SkipRevocationCheck = true
                };

                using (var runspace = RunspaceFactory.CreateRunspace(connectionInfo))
                {
                    try
                    {
                        runspace.Open();

                        using (var pipeline = runspace.CreatePipeline())
                        {
                            // Build the certutil command to add the certificate
                            string script;

                            if (certPath.EndsWith(".pfx", StringComparison.OrdinalIgnoreCase))
                            {
                                script = $"certutil -p \"{certPassword}\" -importpfx \"{storeName}\" \"{certPath}\"";
                            }
                            else if (certPath.EndsWith(".cer", StringComparison.OrdinalIgnoreCase))
                            {
                                script = $"certutil -addstore \"{storeName}\" \"{certPath}\"";
                            }
                            else
                            {
                                Console.WriteLine("Unsupported certificate file format. Please provide a .pfx or .cer file.");
                                return;
                            }

                            // Add the script to the pipeline
                            pipeline.Commands.AddScript(script);

                            try
                            {
                                // Execute the command
                                var results = pipeline.Invoke();

                                // Display the results
                                foreach (var result in results)
                                {
                                    Console.WriteLine(result.ToString());
                                }
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"An error occurred while adding the certificate: {ex.Message}");
                            }
                        }

                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Open?? : {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Connection Error? : {ex.Message}");
            }

        }
    }
}
