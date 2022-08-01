
using DSC_Library;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ConsoleApp1;

internal class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("Getting Certificate");
        X509Certificate2? x509 = CertificateHelper.GetCertificate();
        if (x509 == null) return;

        PrintCertificateInfo(x509);

        Console.WriteLine();

        Console.WriteLine("Validating Certificate");
        var varify = x509.Verify();
        Console.WriteLine($"The certificate is {varify}");

        Console.WriteLine();
        Console.WriteLine("Getting The Chain");


        X509Chain ch = CertificateHelper.GetCertificateChain(x509);
        PrintChainInfo(ch);

        PrintASN_Data(x509);

        /*PrintPrivateKey(x509);*/

        /*PrintStoreLocations();*/

    }

    static void PrintStoreLocations()
    {
        Console.WriteLine("\r\nExists Certs Name and Location");
        Console.WriteLine("------ ----- -------------------------");

        foreach (StoreLocation storeLocation in (StoreLocation[])
            Enum.GetValues(typeof(StoreLocation)))
        {
            foreach (StoreName storeName in (StoreName[])
                Enum.GetValues(typeof(StoreName)))
            {
                X509Store store = new X509Store(storeName, storeLocation);

                try
                {
                    store.Open(OpenFlags.OpenExistingOnly);

                    Console.WriteLine("Yes    {0,4}  {1}, {2}",
                        store.Certificates.Count, store.Name, store.Location);
                }
                catch (CryptographicException)
                {
                    Console.WriteLine("No           {0}, {1}",
                        store.Name, store.Location);
                }
            }
            Console.WriteLine();
        }
    }

    static void PrintCertificateInfo(X509Certificate2 x509)
    {
        Console.WriteLine("{0}Subject: {1}{0}", Environment.NewLine, x509.Subject);
        Console.WriteLine("{0}Issuer: {1}{0}", Environment.NewLine, x509.Issuer);
        Console.WriteLine("{0}Version: {1}{0}", Environment.NewLine, x509.Version);
        Console.WriteLine("{0}Valid Date: {1}{0}", Environment.NewLine, x509.NotBefore);
        Console.WriteLine("{0}Expiry Date: {1}{0}", Environment.NewLine, x509.NotAfter);
        Console.WriteLine("{0}Thumbprint: {1}{0}", Environment.NewLine, x509.Thumbprint);
        Console.WriteLine("{0}Serial Number: {1}{0}", Environment.NewLine, x509.SerialNumber);
        Console.WriteLine("{0}Friendly Name: {1}{0}", Environment.NewLine, x509.PublicKey.Oid.FriendlyName);
        Console.WriteLine("{0}Public Key Format: {1}{0}", Environment.NewLine, x509.PublicKey.EncodedKeyValue.Format(true));
        Console.WriteLine("{0}Raw Data Length: {1}{0}", Environment.NewLine, x509.RawData.Length);
        Console.WriteLine("{0}Certificate to string: {1}{0}", Environment.NewLine, x509.ToString(true));
        Console.WriteLine("{0}Certificate to XML String: {1}{0}", Environment.NewLine, x509.PublicKey.Key.ToXmlString(false));
    }

    static void PrintChainInfo(X509Chain ch)
    {
        Console.WriteLine("Chain Information");
        Console.WriteLine("Chain revocation flag: {0}", ch.ChainPolicy.RevocationFlag);
        Console.WriteLine("Chain revocation mode: {0}", ch.ChainPolicy.RevocationMode);
        Console.WriteLine("Chain verification flag: {0}", ch.ChainPolicy.VerificationFlags);
        Console.WriteLine("Chain verification time: {0}", ch.ChainPolicy.VerificationTime);
        Console.WriteLine("Chain status length: {0}", ch.ChainStatus.Length);
        Console.WriteLine("Chain application policy count: {0}", ch.ChainPolicy.ApplicationPolicy.Count);
        Console.WriteLine("Chain certificate policy count: {0} {1}", ch.ChainPolicy.CertificatePolicy.Count, Environment.NewLine);

        //Output chain element information.
        Console.WriteLine("Chain Element Information");
        Console.WriteLine("Number of chain elements: {0}", ch.ChainElements.Count);
        Console.WriteLine("Chain elements synchronized? {0} {1}", ch.ChainElements.IsSynchronized, Environment.NewLine);

        foreach (X509ChainElement element in ch.ChainElements)
        {
            Console.WriteLine("Element issuer name: {0}", element.Certificate.Issuer);
            Console.WriteLine("Element certificate valid until: {0}", element.Certificate.NotAfter);
            Console.WriteLine("Element certificate is valid: {0}", element.Certificate.Verify());
            Console.WriteLine("Element error status length: {0}", element.ChainElementStatus.Length);
            Console.WriteLine("Element information: {0}", element.Information);
            Console.WriteLine("Number of element extensions: {0}{1}", element.Certificate.Extensions.Count, Environment.NewLine);

            if (ch.ChainStatus.Length > 1)
            {
                for (int index = 0; index < element.ChainElementStatus.Length; index++)
                {
                    Console.WriteLine(element.ChainElementStatus[index].Status);
                    Console.WriteLine(element.ChainElementStatus[index].StatusInformation);
                }
            }
        }
    }

    static void PrintPrivateKey(X509Certificate2 cert)
    {
        Console.WriteLine();
        Console.WriteLine($"Certificate has private key? {cert.HasPrivateKey}");
        RSA? rsa = cert.GetRSAPrivateKey();
        if (rsa == null) return;

        Console.WriteLine($"Private Key: {rsa.ExportRSAPrivateKey()}");
    }

    static void PrintASN_Data(X509Certificate2 cert)
    {
        AsnEncodedDataCollection asncoll = new AsnEncodedDataCollection();
        foreach (X509Extension extension in cert.Extensions)
        {
            // Create an AsnEncodedData object using the extensions information.
            AsnEncodedData asndata = new AsnEncodedData(extension.Oid, extension.RawData);
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Extension type: {0}", extension.Oid.FriendlyName);
            Console.WriteLine("Oid value: {0}", asndata.Oid.Value);
            Console.WriteLine("Raw data length: {0} {1}", asndata.RawData.Length, Environment.NewLine);
            Console.ResetColor();
            Console.WriteLine(asndata.Format(true));
            Console.WriteLine(Environment.NewLine);
            // Add the AsnEncodedData object to the AsnEncodedDataCollection object.
            asncoll.Add(asndata);
        }

        Console.WriteLine(Environment.NewLine);
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("Number of AsnEncodedData items in the collection: {0} {1}", asncoll.Count, Environment.NewLine);
        Console.ResetColor();
    }
}