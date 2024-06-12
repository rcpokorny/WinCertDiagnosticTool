using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WinCertDiagnosticTool
{
    public class CurrentInventoryItem
    {
        //
        // Summary:
        //     The known alias for the inventoried certificate(s)
        public string Alias { get; set; }

        //
        // Summary:
        //     Whether or not the inventoried certificate(s) was found to have a private key
        //     entry
        public bool PrivateKeyEntry { get; set; }

        //
        // Summary:
        //     Reflects the state changes, or lack thereof, of the inventoried item
        public OrchestratorInventoryItemStatus ItemStatus { get; set; }

        //
        // Summary:
        //     Whether or not to use chain level
        public bool UseChainLevel { get; set; }

        //
        // Summary:
        //     The certificate represented by this class. Chain certificates may or may not
        //     be included
        public IEnumerable<string> Certificates { get; set; }

        //
        // Summary:
        //     ASystem.Collections.Generic.Dictionary`2 where the key is an entry parameter
        //     name and the value is the value of the entry parameter
        public Dictionary<string, object> Parameters { get; set; }

    }

    public enum OrchestratorInventoryItemStatus
    {
        Unknown,
        New,
        Modified,
        Deleted,
        Unchanged
    }
}


