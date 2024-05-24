using Keyfactor.Logging;
using Microsoft.Extensions.Logging;
using System.Web.Services.Description;

namespace WinCertDiagnosticTool
{
    internal class Program
    {
        private static ILogger _logger;

        static void Main(string[] args)
        {
            string protocol = "https";
            string clientMachineName = "192.168.230.131";
            string port = "5986";
            bool includePortInSPN = false;

            string serverUsername = "Administrator";
            string serverPassword = "@dminP@ssword#";

            using var myRunspace = PSHelper.GetClientPsRunspace(protocol, clientMachineName, port, includePortInSPN, serverUsername, serverPassword);
            myRunspace.Open();

            myRunspace.Close();
        }
    }
}
