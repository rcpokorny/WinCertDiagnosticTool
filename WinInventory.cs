using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation.Runspaces;
using System.Text;
using System.Threading.Tasks;

namespace WinCertDiagnosticTool
{
    internal class WinInventory : ClientPSCertStoreInventory
    {
        public List<CurrentInventoryItem> GetInventoryItems(Runspace runSpace, string storePath)
        {
            List<CurrentInventoryItem> inventoryItems = new List<CurrentInventoryItem>();

            foreach (Certificate cert in base.GetCertificatesFromStore(runSpace, storePath))
            {
                inventoryItems.Add(new CurrentInventoryItem
                {
                    Certificates = new[] { cert.CertificateData },
                    Alias = cert.Thumbprint,
                    PrivateKeyEntry = cert.HasPrivateKey,
                    UseChainLevel = false,
                    ItemStatus = OrchestratorInventoryItemStatus.Unknown,
                    Parameters = null
                });
            }

            return inventoryItems;
        }
    }
}
