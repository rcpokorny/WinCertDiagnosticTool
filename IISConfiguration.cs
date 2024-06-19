using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WinCertDiagnosticTool
{
    internal class IISConfiguration
    {
        public string SiteName { get; set; }
        public string Port { get; set; }
        public string Protocol { get; set; }
        public string HostName { get; set; }
        public string SniFlag { get; set; }
        public string IPAddress { get; set; }
    }
}
