using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using DistributionEnvelopeTools;

namespace DistributionEnvelopeToolsTest
{
    class Test
    {
        static X509Certificate2 cert1 = null;
        static X509Certificate2 cert2 = null;

        static String c1pfx = "ITKCrypto\\test102.pfx";
        static String c2pfx = "ITKCrypto\\test108.pfx";
        static String sgpfx = "ITKCrypto\\test116.pfx";

        static String c1name = "CN=test102.oneoneone.nhs.uk, OU=ITK Accreditation Services, O=National Integration Centre";
        static String c2name = "CN=test108.oneoneone.nhs.uk, OU=ITK Accreditation Services, O=National Integration Centre";

        static X509Certificate2 sgcert = null;
        static AsymmetricAlgorithm sgpk = null;

        static void loadPfx()
        {
            cert1 = new X509Certificate2(c1pfx, "111test");
            cert2 = new X509Certificate2(c2pfx, "111test");

            sgcert = new X509Certificate2(sgpfx, "111test");
            sgpk = sgcert.PrivateKey;
        }

        static void Main(string[] args)
        {
            loadPfx();
            if (args[0].Equals("write"))
            {
                DistributionEnvelope d = DistributionEnvelope.newInstance();
                d.addRecipient(null, "test:address:one");
                d.setService("dotnet:test:service");
                d.addRecipient("1.2.826.0.1285.0.2.0.107", "123456789012");
                d.addIdentity("1.2.826.0.1285.0.2.0.107", "99999999999");
                d.addSender(null, "test:address:two");
                d.setInteractionId("test_interaction_UK01");
                for (int i = 1; i < args.Length; i++)
                {
                    // Álternate MIME type and file name
                    String mt = args[i++];
                    String file = args[i];
                    String body = null;
                    byte[] content = null;
                    Payload p = new Payload(mt);
                    //bool pack = (i != 2);
                    bool pack = true;
                    if (mt.Contains("xml"))
                    {
                        body = load(file);
                        if (!pack)
                        {
                            p.setProfileId("itk:test:profile-id-v1-0");
                        }
                        p.setBody(body, pack);
                    }
                    else
                    {
                        content = binaryLoad(file);
                        p.setContent(content, pack);
                    }
                    d.addPayload(p);
                    p.addReaderCertificate(cert1);
//                    p.addReaderCertificate(cert2);
                    p.encrypt(sgpk, sgcert);
                }
                String expout = d.ToString();
            }
            else
            {
                String inde = load(args[1]);
                DistributionEnvelopeHelper helper = DistributionEnvelopeHelper.getInstance();
                DistributionEnvelope de = helper.getDistributionEnvelope(inde);
                Payload[] p = helper.getPayloads(de);
                if (p[0].isEncrypted())
                {
                    helper.unpackEncryptedPayload(p[0]);
                    if (p[0].hasKeyForReader("CN=test102.oneoneone.nhs.uk, OU=ITK Accreditation Services, O=National Integration Centre"))
                    {
                        String firstpayload = p[0].decryptTextContent("CN=test102.oneoneone.nhs.uk, OU=ITK Accreditation Services, O=National Integration Centre", cert1.PrivateKey);
                    }
                }
                else
                {
                    String x0 = p[0].getContent();
                    String x1 = p[1].getContent();
                }
                String x = p[0].getBody();
            }

        }

    public static byte[] binaryLoad(String fname)
    {
        byte[] file = null;
        FileStream fis = File.OpenRead(fname);
        int l = (int)((new FileInfo(fname)).Length);
        file = new byte[l];
        int r = -1;
        int ptr = 0;
        while((r = fis.Read(file, ptr, l)) != -1) {
            ptr += r;
            if (ptr == l) {
                break;
            }
        }
        fis.Close();
        return file;
    }
    
    public static String load(String fname) 
    {
        FileStream fis = File.OpenRead(fname);
        StreamReader br = new StreamReader(fis);
        StringBuilder sb = new StringBuilder();
        String line = null;
        while ((line = br.ReadLine()) != null) {
            sb.Append(line);
            sb.Append("\r");
        }
        fis.Close();
        return sb.ToString();
    }

    }
}
