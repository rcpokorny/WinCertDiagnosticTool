using Keyfactor.Logging;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace WinCertDiagnosticTool
{
    public class PSHelper
    {
        private static ILogger _logger;

        public static Runspace GetClientPsRunspace(string winRmProtocol, string clientMachineName, string winRmPort, bool includePortInSpn, string serverUserName,  string serverPassword)
        {
            _logger = LogHandler.GetClassLogger<PSHelper>();
            _logger.MethodEntry();

            // Break the clientMachineName into parts
            string[] parts = clientMachineName.Split('|');

            // Extract the client machine name and arguments based upon the number of parts
            string machineName = parts.Length > 1 ? parts[0] : clientMachineName;
            string? argument = parts.Length > 1 ? parts[1] : null;

            bool isLocal = (machineName.ToLower() == "localhost") || (argument != null && argument.ToLower() == "localmachine");

            if (isLocal)
            {
                return RunspaceFactory.CreateRunspace();
            }
            else
            {
                var connInfo = new WSManConnectionInfo(new Uri($"{winRmProtocol}://{clientMachineName}:{winRmPort}/wsman"));
                connInfo.IncludePortInSPN = includePortInSpn;

                _logger.LogTrace($"Creating remote session at: {connInfo.ConnectionUri}");

                if (!string.IsNullOrEmpty(serverUserName))
                {
                    _logger.LogTrace($"Credentials Specified");
                    var pw = new NetworkCredential(serverUserName, serverPassword).SecurePassword;
                    connInfo.Credential = new PSCredential(serverUserName, pw);
                }
                return RunspaceFactory.CreateRunspace(connInfo);
            }
        }
    }
}
