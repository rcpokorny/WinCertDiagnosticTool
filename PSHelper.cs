// Ignore Spelling: Spn

using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation.Runspaces;
using System.Management.Automation;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace WinCertDiagnosticTool
{
    public class PSHelper
    {
        public static Runspace GetClientPsRunspace(string winRmProtocol, string clientMachineName, string winRmPort, bool includePortInSpn, string serverUserName, string serverPassword)
        {
            // 2.4 - Client Machine Name now follows the naming conventions of {clientMachineName}|{localMachine}
            // If the clientMachineName is just 'localhost', it will maintain that as locally only (as previosuly)
            // If there is no 2nd part to the clientMachineName, a remote PowerShell session will be created

            // Break the clientMachineName into parts
            string[] parts = clientMachineName.Split('|');

            // Extract the client machine name and arguments based upon the number of parts
            string machineName = parts.Length > 1 ? parts[0] : clientMachineName;
            string? argument = parts.Length > 1 ? parts[1] : null;

            // Determine if this is truly a local connection
            bool isLocal = (machineName.ToLower() == "localhost") || (argument != null && argument.ToLower() == "localmachine");

            if (isLocal)
            {
                //return RunspaceFactory.CreateRunspace();
                PowerShellProcessInstance instance = new PowerShellProcessInstance(new Version(5, 1), null, null, false);
                Runspace rs = RunspaceFactory.CreateOutOfProcessRunspace(new TypeTable(Array.Empty<string>()), instance);

                return rs;
            }
            else
            {

                var connInfo = new WSManConnectionInfo(new Uri($"{winRmProtocol}://{clientMachineName}:{winRmPort}/wsman"));
                connInfo.IncludePortInSPN = includePortInSpn;

                if (!string.IsNullOrEmpty(serverUserName))
                {
                    var pw = new NetworkCredential(serverUserName, serverPassword).SecurePassword;
                    connInfo.Credential = new PSCredential(serverUserName, pw);
                }
                return RunspaceFactory.CreateRunspace(connInfo);
            }
        }
    }
}
