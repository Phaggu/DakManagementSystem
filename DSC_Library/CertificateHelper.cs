using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Permissions;

namespace DSC_Library;

public static class CertificateHelper
{
    public static X509Certificate2? GetCertificate()
    {
        X509Certificate2? cert = null;

        X509Store store_localMachine = new("MY", StoreLocation.LocalMachine);
        X509Store store_currentUser = new("MY", StoreLocation.CurrentUser);
        store_localMachine.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
        store_currentUser.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

        X509Certificate2Collection collection = store_localMachine.Certificates;
        collection.AddRange(store_currentUser.Certificates);
        X509Certificate2Collection sCollection = X509Certificate2UI.SelectFromCollection(collection, "Certificate Select", "Select a Certificate from the list", X509SelectionFlag.SingleSelection);
        if (sCollection.Count == 0) return cert;
        cert = sCollection[0];
        store_localMachine.Close();
        store_currentUser.Close();  
       
        return cert;
    }

    public static X509Chain GetCertificateChain(X509Certificate2 cert)
    {
        X509Chain chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
        chain.Build(cert); 

        return chain;
    }

    

    
}
