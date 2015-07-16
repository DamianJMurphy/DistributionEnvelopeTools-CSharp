using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace DistributionEnvelopeTools
{
    /** 
     * Representation of a payload plus its metadata from the distribution envelope manifest.
     *
     */
    public class Payload
    {
        private const int UNCOMPRESSBUFFERSIZE = 10240;
        private const int AESKEYSIZE = 256;
        private const int DATAENCIPHERMENTUSAGE = 3;
        private const int KEYENCIPHERMENTUSAGE = 2;

        private const int IVLENGTH = 16;

        /**
         * This is set false here for the default behaviour that requires certificates
         * to have been issued with a "key usage" extension. It is NOT unset anywhere,
         * and there is no configuration setting to make it true (and hence to accept
         * certificates that have no key usage extension). If there is a need in a 
         * particular case to accept such certificates, change this here as a compile
         * time option - or modify the code to support a configuration option.
         */
        // private bool allowNonUsageCertificates = false;

        // FOR TESTING - we're testing functionality without the "KeyUsage" extension
        // in the certificates, so allow certificates without the extension for now.
        //
        private bool allowNonUsageCertificates = true;

        private List<X509Certificate> readerCerts = new List<X509Certificate>();
        private String encryptedContent = null;
        private Dictionary<String, String> receivedReaders = null;

        private String manifestId = null;
        private String mimeType = null;
        private String profileId = null;
        private bool base64 = false;
        private bool compressed = false;
        private bool encrypted = false;
    
        private bool unmunged = false;
    
        private String payloadBody = null;
    
        /**
         * Public Payload constructor called by senders making a DistributionEnvelope.
         * 
         * @param m Payload MIME type.
         */ 
        public Payload(String m) {
            manifestId = "uuid_" + System.Guid.NewGuid().ToString().ToLower();
            mimeType = m;
        }
    
        /**
         * Internal Payload constructor called by the DistributionEnvelopeHelper when
         * parsing received XML.
         */ 
        internal Payload(String id, String m, String p, String b, String c, String e) {
            manifestId = id;
            mimeType = m;
            if (p.Length > 0) {
                    profileId = p;
            }
            base64 = (b.Equals("true"));
            compressed = (c.Equals("true"));
            encrypted = (e.Equals("true"));
        }


        /**
         * Called by the DistributionEnvelopeHelper to write base64 encoded ciphertext
         * for the payload.
         * 
         * @param ec 
         */
        internal void setEncryptedContent(String ec)
        {
            encryptedContent = ec;
            receivedReaders = new Dictionary<String, String>();
        }

        /**
         * Called by the DistributionEnvelopeHelper to record an encrypted symmetric
         * key, and the associated public key name. Note that this is internal and
         * expects to be called from the helper, because it assumes that the helper
         * has set the encrypted content first (which creates the HashMap into which
         * the reader details are written).
         * 
         * @param n Public key name
         * @param k Base64 encrypted symmetric key
         */
        internal void addReceivedReader(String n, String k)
        {
            receivedReaders.Add(n, k);
        }

        /**
         * Validity date range check on certificate.
         * 
         * @param r 
         */
        private bool checkCertificateDateRange(X509Certificate2 r)
        {
            DateTime now = DateTime.Now;
            if (now.CompareTo(r.NotBefore) < 0)
            {
                return false;
            }
            return (now.CompareTo(r.NotAfter) < 0);
        }

        /**
         * Key usage check on the certificate: returns true if "data encipherment" usage is found
         * or the usage check is turned off.
         */
        private bool checkKeyUsage(X509Certificate2 r)
        {
            bool hasDataEnciphermentUsage = false;
            X509ExtensionCollection ext = r.Extensions;
            if ((ext == null) && !allowNonUsageCertificates)
            {
                throw new Exception("Certificate " + r.SubjectName.Name + " has no key usage extension");
            }
            foreach (X509Extension x in ext)
            {
                if (x.Oid.FriendlyName == "Key Usage")
                {
                    X509KeyUsageExtension ku = (X509KeyUsageExtension)x;
                    hasDataEnciphermentUsage = ku.KeyUsages.HasFlag(X509KeyUsageFlags.DataEncipherment);
                    break;
                }
            }
            if (!hasDataEnciphermentUsage && !allowNonUsageCertificates)
            {
                throw new Exception("Certificate " + r.SubjectName.Name + " not valid for data encipherment");
            }
            // This part has NOT been ported from the Java, but the comment is retained:
            //
            // This is included but commented out specifically to make the point that
            // section 4.2.1.3, "Key Usage" in RFC2459 says that the "key encipherment"
            // usage is for key management, so it isn't relevant here.
            //
            //        if (!usage[KEYENCIPHERMENTUSAGE]) {
            //            throw new Exception("Certificate " + r.getSubjectDN().getName() + " not valid for key encipherment");
            //        }
            return true;
        }

        /**
         * Add an X.509 certificate for a recipient.
         * 
         * @param r 
         */
        public void addReaderCertificate(X509Certificate2 r) 
        { 
            if (r == null) {
                throw new Exception("Null certificate");
            }
            // Date range check against current date and time
            //
            if (!checkCertificateDateRange(r))
            {
                throw new Exception("Invalid certificate: out of date range");
            }
        
            // Allowed use check. Need to check that the certificate is issued
            // for usages that include "data encipherment". By default, require a
            // "key usage" extension unless the compile-time "allowNonUsageCertificates"
            // has been set.
            //
            if (!checkKeyUsage(r))
            {
                throw new Exception("Certificate " + r.Subject + " not valid for data encipherment");
            }
            encrypted = true;
            readerCerts.Add(r); 
        }

        /**
         * Common payload content encryption method which is called after sanity
         * checks, and after any content signing is performed.
         * 
         * @throws Exception 
         */
        private void doEncryption()
        {
            // Make the one-time symmetric key, and encrypt the payload content using it.
            String cipherData = null;
            byte[] key = null;
            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                aes.KeySize = AESKEYSIZE;
                aes.GenerateKey();
                key = aes.Key;
                aes.IV = getInitialisationVector();
                cipherData = doAESEncryption(aes);
            }

            // Start constructing the XML Encryption "EncryptedData" element. The main 
            // payload encryption is AES-256/CBC
            //
            StringBuilder sb = new StringBuilder("<xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\">");
            sb.Append("<xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes256-cbc\"/>");

            // And then the KeyInfo which is the symmetric key byte[] encrypted for each
            // reader certificate.
            //
            sb.Append("<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">");
            foreach (X509Certificate2 x in readerCerts)
            {
                sb.Append(doRSASymmetricKeyEncryption(x, key));
            }
            sb.Append("</ds:KeyInfo>");
            sb.Append(cipherData);
            sb.Append("</xenc:EncryptedData>");

            // Set the payloadBody to the EncryptedData, and the "encrypted" flag to "true".
            // Note that "base64" and "compressed" apply to the *cleartext*, and so are not
            // altered by this operation. The same goes for the mime type. Receiving systems
            // that decrypt the payload will need these other data set correctly in order to
            // convert the encrypted and possibly otherwise-processed content into something
            // they can use.
            //
            payloadBody = sb.ToString();
            encrypted = true;

            // Make sure we overwrite the key byte[] before we leave, and mark the
            // one-time secret key null.
            //
            for (int i = 0; i < key.Length; i++)
            {
                key[i] = 0;
            }
            key = null;
        }

        /**
         * Encrypt the payload content, but sign it using the given PrivateKey and
         * X509Certificate using an enveloping signature, before encrypting.
         * 
         * @param pk private key
         * @param cert certificate associated with private key
         * @throws Exception 
         */
        public void encrypt(AsymmetricAlgorithm pk, X509Certificate2 cert)
        {
            if (readerCerts.Count == 0)
            {
                throw new Exception("No recipient public keys");
            }
            if (payloadBody == null)
            {
                throw new Exception("Attempt to encrypt empty content");
            }
            signPayload(pk, cert);
            doEncryption();        
        }

        /**
         * Sign the payloadBody as-is. Note that this is going to be encrypted anyway
         * so we avoid any incompatibilities due to canonicalisation, and we don't
         * care if the payloadBody is text, compressed and so on. Re-writes payloadBody
         * with a serialised XML Digital Signature "Signature" element containing an
         * enveloping signature, or throws an exception to signal failure. 
         * 
         * @param pk Private key
         * @param cert certificate associated with private key
         * @throws Exception 
         */
        private void signPayload(AsymmetricAlgorithm pk, X509Certificate2 cert)
        {
            if ((pk == null) || (cert == null))
            {
                throw new Exception("Null signing material");
            }
            if (!checkCertificateDateRange(cert))
            {
                throw new Exception("Cannot use certificate " + cert.SubjectName + " as it is out of date");
            }
            Reference reference = null;
            DataObject dataObject = null;
            XmlDocument doc = new XmlDocument();
            String objectRef = "uuid" + Guid.NewGuid().ToString().ToLower();
            reference = new Reference("#" + objectRef);
            if (compressed || base64 || !mimeType.Contains("xml"))
            {
                // Reference to the encoded binary content, using the (default) SHA1 DigestMethod
                //
                dataObject = new DataObject();
                XmlText t = doc.CreateTextNode(payloadBody);

                // This element is just created as a workaround to contain the text, because .Net
                // won't let us include an XmlTextNode directly like the JDK will. We actually
                // grab the text node back out again in an XmlNodeList, which seems to keep the
                // .Net signer happy.
                //
                XmlElement element = doc.CreateElement("X");
                element.AppendChild(t);
                XmlNodeList nl = element.ChildNodes;
                dataObject.Data = nl;
            }
            else
            {
                // Reference to the XML payload, using the (default) SHA1 DigestMethod and
                // exclusive canonicalisation.
                //
                reference.AddTransform(new XmlDsigExcC14NTransform());
                doc.LoadXml(payloadBody);
                dataObject.Data = doc.ChildNodes;
            }
            dataObject.Encoding = "";
            dataObject.Id = objectRef;
            dataObject.MimeType = "";
            SignedXml signedXml = new SignedXml();
            signedXml.AddObject(dataObject);
            signedXml.AddReference(reference);
            signedXml.SigningKey = pk;
            KeyInfo ki = new KeyInfo();
            ki.AddClause(new KeyInfoX509Data(cert));
            signedXml.KeyInfo = ki;
            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigC14NWithCommentsTransformUrl;
            signedXml.ComputeSignature();
            payloadBody = signedXml.Signature.GetXml().OuterXml;
        }

        /**
         * Encrypt the payload content for the given reader certificates. According to 
         * XML Encryption specification and the ITK details.
         * 
         * @throws Exception If there are no reader certificates, if the content is empty, or if something else goes wrong in the process.
         */
        public void encrypt()
        { 
            if (readerCerts.Count == 0) {
                throw new Exception("No recipient public keys");
            }
            if (payloadBody == null) {
                throw new Exception("Attempt to encrypt empty content");
            }
            doEncryption();        
        }

        /**
         * Creates an XML Encryption "EncryptedKey" element using. Note that this does
         * NOT check the signing chain of the given certificate - the caller is responsible
         * for doing that since it makes assumptions about the availability of verification
         * and CRL information that the DistributionEnvelopeTools package cannot know about.
         * 
         * Note also that this made to encrypt 256 bit AES-256 keys. The Cipher.doFinal() call
         * used will handle this data size, but it has a maximum of 256 bytes - so if the code
         * is used for symmetric keys of 256 bytes or larger, it will need to be re-factored to
         * loop through the larger key.
         * 
         * @param cert X.509v3 certificate containing the reader's public key
         * @param k Symmetric key material
         * @return Serialised "EncryptedKey" element.
         * @throws Exception If something goes wrong.
         */
        private String doRSASymmetricKeyEncryption(X509Certificate2 cert, byte[] k)
        {
            // Encrypt the symmetric key using the given certificate...
            //
            RSACryptoServiceProvider rsa = (RSACryptoServiceProvider)cert.PublicKey.Key;
            byte[] c = rsa.Encrypt(k, false);
        
            // ... then base64 encode the ciphertext and store it in an EncryptedKey
            // element, noting that the key is encrypted using RSA 1.5
            //
            StringBuilder sb = new StringBuilder("<xenc:EncryptedKey><EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-1_5\"/>");
        
            // Record the "reader" using the subject Distinguished Name of the given certificate,
            // and store it in the "KeyName" element. Receivers will use this to match "their" copy
            // of the encrypted symmetric key, with the private key they hold.
            //
            sb.Append("<ds:KeyInfo><ds:KeyName>");
            sb.Append(cert.Subject);
            sb.Append("</ds:KeyName></ds:KeyInfo>");
            sb.Append("<xenc:CipherData><xenc:CipherValue>");
            sb.Append(Convert.ToBase64String(c));
            sb.Append("</xenc:CipherValue></xenc:CipherData>");
            sb.Append("</xenc:EncryptedKey>");
            return sb.ToString();        
        }
    
        /**
         * Encrypt the payload content using AES-256. Return it as an
         * XML Encryption "CipherData" element with the base64 encoded ciphertext.
         * 
         * @param key Symmetric secret key
         * @return String containing a serialised CipherData element with the encrypted payload base64 encoded.
         * @throws Exception 
         */
        private String doAESEncryption(AesCryptoServiceProvider aes)
        {
            aes.Padding = PaddingMode.PKCS7;
            aes.Mode = CipherMode.CBC;

            // The IV is made from the first 16 bytes of the payload manifest id.
            //
            byte[] iv = getInitialisationVector();
            aes.IV = iv;

            byte[] c = null;
            using (ICryptoTransform cipher = aes.CreateEncryptor())
            {
                byte[] content = Encoding.UTF8.GetBytes(payloadBody);
                c = cipher.TransformFinalBlock(content, 0, content.Length);
            }
            StringBuilder sb = new StringBuilder("<xenc:CipherData><xenc:CipherValue>");
            sb.Append(Convert.ToBase64String(c));
            sb.Append("</xenc:CipherValue></xenc:CipherData>");
            return sb.ToString();        
        }
    
        /**
         * Checks to see if an encrypted payload has a symmetric key encrypted for
         * the given reader key name.
         * 
         * @param s Key name to check.
         * @return True if it does, false if not or there are no symmetric key encryptions.
         */
        public bool hasKeyForReader(String s) {
            if (receivedReaders == null) {
                return false;
            }
            return receivedReaders.ContainsKey(s);
        }
    
        /**
         * Make an IV for the AES encryption. This needs to be the same for both the
         * encryption and decryption and, if unspecified, the Cipher will make a new one
         * in each case - so the content won't be able to be decrypted. Use the first 
         * 16 bytes of the payload's manifest id as an IV.
         * 
         * @return IvParameter spec made from the data as described.
         * @throws Exception 
         */
        private byte[] getInitialisationVector()
        {        
            byte[] iv = new byte[IVLENGTH];
            for (int i = 0; i < IVLENGTH; i++) {
                iv[i] = 0;
            }
            int j = (manifestId.StartsWith("uuid")) ? 4 : 0;
            byte[] id = Encoding.UTF8.GetBytes(manifestId);            
            for (int i = 0; i < manifestId.Length; i++ ) {
                if (i == IVLENGTH)
                    break;
                iv[i] = id[i + j];
            }
            return iv;
        }

        /**
         * Returns the payload content as a string - this is only suitable for "stringable"
         * payloads (determined by MIME type) and will throw an exception otherwise. Any
         * compression or base64 decoding that is required will be handled as indicated
         * by the relevant flags in the Payload instance.
         * 
         * @param keyname Subject DN of the certificate containing the public key, used to
         * identify which encrypted symmetric key needs to be decrypted to access the content.
         * @param privatekey Private key corresponding to the public key with the given Subject DN
         * @return Decrypted and decoded text content, as a string.
         * @throws Exception 
         */
        public String decryptTextContent(String keyname, AsymmetricAlgorithm privatekey)
        {
            byte[] decrypted = decrypt(keyname, privatekey);
            if (decrypted == null)
            {
                return "";
            }
            String p = Encoding.UTF8.GetString(decrypted);
            return getTextContent(p);
        }

        /**
         * Returns the payload as a byte array. This does no checking of MIME type and
         * is therefore suitable for binary content that has no string representation.
         * Handles de-compression and base64 decoding as indicates by the flags in the
         * payload.
         * @param keyname Subject DN of the certificate containing the public key, used to
         * identify which encrypted symmetric key needs to be decrypted to access the content.
         * @param privatekey Private key corresponding to the public key with the given Subject DN
         * @return Decrypted and decoded text content, as a byte array.
         * @throws Exception 
         */
        public byte[] decryptRawContent(String keyname, AsymmetricAlgorithm privatekey)
        {
            byte[] decrypted = decrypt(keyname, privatekey);
            if (decrypted == null)
            {
                return null;
            }
            String p = Encoding.UTF8.GetString(decrypted);
            return demungeRawContent(p);
        }


        /**
         * Use the given private key and name to decrypt the payload body and return
         * it as a string. The decrypted content is NOT RETAINED in this instance of
         * Payload.
         * 
         * @param keyname Name of the public key used to encrypt the symmetric key
         * @param privatekey Associated private key. The caller is responsible for passwords and other retrieval operations
         * @return Decrypted payload as a byte array. It is up to the caller to use the various payload flags and MIME type to determine what it wants to do with the decrypt.
         * @throws Exception If anything goes wrong in the process.
         */
        private byte[] decrypt(String keyname, AsymmetricAlgorithm privatekey)
        {
            
            if (!encrypted) {
                throw new Exception("Not encrypted");
            }
            if (!hasKeyForReader(keyname)) {
                throw new Exception("No such key");
            }
        
            // Base64-decode the encrypted symmetric key for the given keyname (note the 
            // point above, under encryption, about the maximum size of this symmetric key
            // to do this operation with a single call to doFinal()).
            //
            byte[] decrypted = null; 
            byte[] ekey = Convert.FromBase64String(receivedReaders[keyname]);
            using (RSACryptoServiceProvider rsa = (RSACryptoServiceProvider)privatekey)
            {
                byte[] symmetrickey = rsa.Decrypt(ekey, false);
                using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
                {
                    aes.Padding = PaddingMode.PKCS7;
                    aes.Mode = CipherMode.CBC;
                    aes.Key = symmetrickey;
                    // The IV is made from the first 16 bytes of the payload manifest id.
                    //
                    byte[] iv = getInitialisationVector();
                    aes.IV = iv;
                    // Then use the decrypted symmetric key to decrypt the payload content.
                    // This must use the same Initialisation Vector as the encryption operation,
                    // so make the IV from the first 16 bytes of the manifest id. The payload
                    // ciphertext will need base64 decoding first.
                    //
                    byte[] enc = Convert.FromBase64String(encryptedContent);
                    using (ICryptoTransform cipher = aes.CreateDecryptor())
                    {
                        // And do the decrypt. Need to check the behaviour of this for "large" payloads.
                        //
                        decrypted = cipher.TransformFinalBlock(enc, 0, enc.Length);
                    }
                }
            }
                
            // This method should return the decrypted byte array. It is up to the caller to 
            // check the manifest data - mime type, compressed flag and base64 to determine 
            // what to do with the decrypted data, because generically we don't know what it
            // is or how to handle it here.
            //
            return checkSignature(decrypted);
        }

        /**
         * Handle signed content after decryption. The content is signed and encrypted
         * separately, and when a payload is decrypted it may or may not be signed. This
         * method checks if the payload has been signed: if not it is returned unchanged.
         * If the content has been signed, the signature is verified before the content
         * that was signed, is returned.
         * @param decrypted Decrypted 
         * @return
         * @throws Exception If the signature verification fails.
         */
        private byte[] checkSignature(byte[] decrypted)
        {
            String tryXml = null;
            try
            {
                tryXml = Encoding.UTF8.GetString(decrypted);
            }
            catch
            {
                return decrypted;
            }
            XmlDocument xmldoc = new XmlDocument();
            try {
                xmldoc.LoadXml(tryXml);
            }
            catch
            {
                return decrypted;
            }
            if (!xmldoc.FirstChild.LocalName.Equals("Signature"))
            {
                return decrypted;
            }
            if (!xmldoc.FirstChild.NamespaceURI.Equals("http://www.w3.org/2000/09/xmldsig#"))
            {
                return decrypted;
            }
            SignedXml signedXml = new SignedXml(xmldoc);
            signedXml.LoadXml((XmlElement)xmldoc.GetElementsByTagName("Signature")[0]);
            if (!signedXml.CheckSignature())
            {
                throw new Exception("Signature validation failed");
            }
            return getSignatureObject(signedXml);
        }

        /**
         * Extracts the content of an "Object" element element of the enveloping 
         * signature - see the W3 XML Encryption specification.
         * @param signature
         * @return
         * @throws Exception 
         */
        private byte[] getSignatureObject(SignedXml x)
        {
            XmlElement s = x.Signature.GetXml();
            XmlNodeList nl = s.GetElementsByTagName("Object", "http://www.w3.org/2000/09/xmldsig#");
            if (nl.Count == 0)
            {
                throw new Exception("Error retrieving object from signature");
            }
            String obj = ((XmlElement)nl.Item(0)).InnerText;
            return Encoding.UTF8.GetBytes(obj);
        }

        /**
         * @param prefix Prefix to use for the ITK XML namespace.
         * 
         * @returns String containing the manifestitem element for this payload.
         */ 
        public String makeManifestItem(String prefix) 
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("<");
            sb.Append(prefix);
            sb.Append(":manifestitem mimetype=\"");
            sb.Append(mimeType);
            sb.Append("\"");
            if (profileId != null) {
                sb.Append(" profileid=\"");
                sb.Append(profileId);
                sb.Append("\"");
            }
            sb.Append(" base64=\"");
            sb.Append(serialiseBoolean(base64));
            sb.Append("\" compressed=\"");
            sb.Append(serialiseBoolean(compressed));
            sb.Append("\" encrypted=\"");
            sb.Append(serialiseBoolean(encrypted));
            sb.Append("\" id=\"");
            sb.Append(manifestId);
            sb.Append("\"/>");
            return sb.ToString();
        }

        /**
         * Returns binary content when not encrypted, with compression and base64 
         * encoding un-done.
         * @return
         * @throws Exception 
         */
        public byte[] getRawContent()
        {
            if (encrypted) {
                throw new Exception("Encrypted body");
            }
            return demungeRawContent(payloadBody);        
        }

        /**
         * Un-do treatments such as compression and base64 encoding.
         * @param t
         * @return
         * @throws Exception 
         */
        private byte[] demungeRawContent(String t) 
        { 
            if (compressed) {
                return decompressBody(t);
            }
            if (base64) {
                return Convert.FromBase64String(t);
            }
            return Encoding.UTF8.GetBytes(t); 
        }

        /**
         * Turn a "bool" into something sensible for XML.
         */
        private string serialiseBoolean(bool b)
        {
            if (b) return "true";
            return "false";
        }

        /**
         * Sets the profile id for the manifestitem, this is not validated and it
         * is the caller's responsibility to set the correct value.
         */ 
        public void setProfileId(String p) { profileId = p; }
    
        /**
         * Sets and optionally tries to compress the payload body as a string. 
         * 
         * If requested, the method will compress the body, but will only retain
         * the compressed form if a ratio > 1.34 is obtained, to cover the overhead 
         * of base64 encoding the compressed data.
         * 
         * @param b Payload body
         * @param pack Should the method attempt to compress the body.
         */ 
        public void setBody(String b, bool pack) 
        { 
            payloadBody = b;
            if (!pack) {
                return;
            }
            compressIfViable(Encoding.UTF8.GetBytes(b));
        }

        /**
         * Compress the content according to the RFC1952 GZip algorithm. Since 
         * compression produces binary output, to fit
         * into an XML document the output has to be base64 encoded, which results 
         * in a 33% increase in size. So the compressed form is only "accepted" if
         * the attempt results in an overall reduction in size.
         * 
         * @param content
         * @throws Exception 
         */
        private void compressIfViable(byte[] content)
        {
            byte[] comp = null;
            using (MemoryStream compressedOutput = new MemoryStream())
            {
                using (GZipStream gzOut = new GZipStream(compressedOutput, CompressionMode.Compress))
                {
                    gzOut.Write(content, 0, content.Length);
                }
                comp = compressedOutput.ToArray();
            }
            double ratio = (double)content.Length / (double)comp.Length;
            if (ratio > 1.34d) {
                long complength = (long)((4.0d/3.0d) * comp.Length);
                if ((complength % 4) != 0)
                {
                    complength += 4 - (complength % 4);
                }
                char[] c = new char[complength];
                Convert.ToBase64CharArray(comp, 0, comp.Length, c, 0);
                content = new byte[complength];
                for (int i = 0; i < complength; i++)
                {
                    content[i] = (byte)c[i];
                }
                payloadBody = Convert.ToBase64String(comp);
                base64 = false;
                compressed = true;
            } else {
                payloadBody = Convert.ToBase64String(content);
                base64 = true;
                compressed = false;            
            }       
        }

        /**
         * Sets and optionally tries to compress the payload body as a byte
         * array. In either case the data is base64 encoded. 
         * 
         * If requested, the method will compress the body, but will only retain
         * the compressed form if a ratio > 1.34 is obtained, to cover the overhead 
         * of base64 encoding the compressed data.
         * 
         * @param b Payload body
         * @param pack Should the method attempt to compress the body.
         */ 
        public void setContent(byte[] data, bool pack)
        {
            if (!pack) {
                base64 = true;
                payloadBody = Convert.ToBase64String(data);
                return;
            }
            compressIfViable(data);
        }
    
        /**
         * Allows the sender to "manually" set (or unset) the base64 flag,
         * for example where a payload is provided which is already so
         * encoded.
         */ 
        public void setBase64(bool b) { base64 = b; }

        /**
         * Allows the sender to "manually" set (or unset) the compressed flag,
         * for example where a payload is provided which is already compressed.
         * If set true, the base64 flag is also set.
         */ 
        public void setCompressed(bool c) 
        { 
            compressed = c;
            if (c)
            {
                base64 = true;
            }
        }
    
        /**
         * Sets the encrypted flag. Reserved for future use.
         */ 
        public void setEncrypted(bool e) { encrypted = e; }      
    
        public bool isBase64() { return base64; }
        public bool isCompressed() { return compressed; }
        public bool isEncrypted() { return encrypted; }
        public bool isDecoded() { return unmunged; }
        public String getMimeType() { return mimeType; }
        public String getManifestId() { return manifestId; }
        public String getProfileId() { return profileId; }
        public String getBody() { return payloadBody; }

        /**
         * Gets clear-text content as a String, checks
         * @return The content as a string.
         * @throws Exception If the content is encrypted, not representable as a string, or any decoding operations fail.
         */
        public String getContent() 
        {
            if (encrypted) {
                throw new Exception("Encrypted body");
            }
            return getTextContent(payloadBody);
        }

        /**
         * Return decompressed content.
         * @param t Base64 encoded string containing the compressed content.
         * @return
         * @throws Exception 
         */
        private byte[] decompressBody(String t)
        {
            byte[] content = null;
            using (MemoryStream uncomp = new MemoryStream())
            {
                using (GZipStream gzIn = new GZipStream(new MemoryStream(Convert.FromBase64String(t)), CompressionMode.Decompress))
                {
                    byte[] buffer = new byte[UNCOMPRESSBUFFERSIZE];
                    int l = -1;
                    while ((l = gzIn.Read(buffer, 0, UNCOMPRESSBUFFERSIZE)) != 0)
                    {
                        uncomp.Write(buffer, 0, l);
                    }
                    content = uncomp.GetBuffer();
                }
            }
            return content;
        }

        /**
         * For payload content which is representable as an un-encoded (including
         * base64) string. Checks for and un-does base64 encoding or compression
         * as required.
         * 
         * @param t Content, possibly encoded or compressed.
         * @return Content as a string.
         * @throws Exception If the content is not representable as a string, or if any other decoding process goes wrong.
         */
        private String getTextContent(String t) 
        { 
            if (!stringable()) {
                throw new Exception("Not stringable - use getRawContent()");
            }
            if (compressed) {
                byte[] uncomp = decompressBody(t);
                return Encoding.UTF8.GetString(uncomp);
            }
            else
            {
                if (base64) {
                    return Encoding.UTF8.GetString(Convert.FromBase64String(t));
                }
            }
            return t; 
        }

        /**
         * Called by DistributionEnvelopeHelper
         */ 
        internal void setContent(String pb)
        {
            payloadBody = pb;
        }

        /**
         * Is it meanigful to return this content as an un-encoded string ?
         * @return 
         */
        private bool stringable(){
            // Just make some simple inferences from the MIME type
            //
            if (mimeType == null) return false;
            if (mimeType.StartsWith("text")) return true;
            if (mimeType.StartsWith("application") && mimeType.ToLower().Contains("xml")) return true;
            return false;
        }
    
        internal void loadBody(String b) {
        
        }

    }
}
