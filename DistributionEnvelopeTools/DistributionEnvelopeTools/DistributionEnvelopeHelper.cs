using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Xsl;
/*
Copyright 2012 Damian Murphy <murff@warlock.org>

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */
namespace DistributionEnvelopeTools
{
    /**
     * Singleton helper class for parsing received DistributionEnvelope XML.
     */ 
    public class DistributionEnvelopeHelper
    {
        private const int BUFFERSIZE = 1024;
        private const String EXTRACT_TRANSFORM = "DistributionEnvelopeTools.distribution-envelope-extractor.xslt";
        private const String EXTRACT_START_DELIMITER = "<!--";
        private const String EXTRACT_END_DELIMITER = "-->";

        private const String PAYLOAD_EXTRACT_TRANSFORM = "DistributionEnvelopeTools.distribution_envelope_payload_extractor.xslt";
        private static String[] PAYLOAD_DELIMITER = {"#-#-#-#-#-#-#-#-#"};
        private static String[] PAYLOAD_FIELD_DELIMITER = {"####"};
        private static String[] EQUALS_DELIMITER = {":="};

        private const String ENCRYPTEDDATA_EXTRACT_TRANSFORM = "DistributionEnvelopeTools.encrypted_data_extractor.xslt";

        private static DistributionEnvelopeHelper me = new DistributionEnvelopeHelper();
        private static Exception initialException = null;

        private XslCompiledTransform distributionEnvelopeExtractor = null;
        private XslCompiledTransform payloadExtractor = null;
        private XslCompiledTransform encryptedDataExtractor = null;

        private Dictionary<string, List<string>> checkClasses = null;
        private static string[] CHECK_CLASS_DELIMITER = { "," };

        private DistributionEnvelopeHelper()
        {
            try
            {
                distributionEnvelopeExtractor = loadTransform(EXTRACT_TRANSFORM);
                payloadExtractor = loadTransform(PAYLOAD_EXTRACT_TRANSFORM);
                encryptedDataExtractor = loadTransform(ENCRYPTEDDATA_EXTRACT_TRANSFORM);
            }
            catch (Exception e)
            {
                initialException = e;
                EventLog logger = new EventLog("Application", ".", DistributionEnvelopeException.SYSTEM_LOGGER);
                logger.WriteEntry(e.ToString(), EventLogEntryType.Error);
            }
        }

        /**
         * @returns Singleton DistributionEnvelopeHelper
         * @throws Any initialisation exception
         */ 
        public static DistributionEnvelopeHelper getInstance() 
        {  
            if (initialException != null) {
                throw initialException;
            }
            return me; 
        }

        private XslCompiledTransform loadTransform(String name)
        {
            Assembly assembly = Assembly.GetExecutingAssembly();
            Stream extractor = assembly.GetManifestResourceStream(name);
            XmlTextReader xrdr = new XmlTextReader(extractor);
            XslCompiledTransform xct = new XslCompiledTransform();
            xct.Load(xrdr);
            return xct;
        }

        /**
         * Add a list of class names implementing IDistributionEnvelopeChecker for a service name, or
         * for the special value "all". Class names are of the form [Assembly:]Namespace.Class where
         * Assembly can be provided if the check class is not in "DistributionEnvelopeTools". The list is comma-
         * delimited.
         */ 
        public void addCheckClassnames(string svc, string classList)
        {
            if (checkClasses == null)
                checkClasses = new Dictionary<string, List<string>>();
            if (!checkClasses.ContainsKey(svc))
                checkClasses.Add(svc, new List<string>());
            List<string> l = checkClasses[svc];
            string[] classes = classList.Split(CHECK_CLASS_DELIMITER, StringSplitOptions.None);
            foreach (string c in classes)
            {
                l.Add(c);
            }
        }

        public void unpackEncryptedPayload(Payload p)
        {
            // Run an XSL transform to extract from the PayloadBody:
            //
            // 1. The encrypted keys as N=keyname####K=base64encodedkey pairs
            // 2. A "payload delimiter" (static)
            // 3. The base64 encoded ciphertext
            //
            // Get that as a text string, then split it up and add it to the
            // Payload
            StringWriter extractBuffer = new StringWriter();
            XmlTextWriter extractWriter = new XmlTextWriter(extractBuffer);
            StringReader sr = new StringReader(p.getBody());
            XmlTextReader rdr = new XmlTextReader(sr);
            encryptedDataExtractor.Transform(rdr, extractWriter);

            String[] parts = extractBuffer.GetStringBuilder().ToString().Split(PAYLOAD_DELIMITER, StringSplitOptions.None);
            if (parts.Length != 2) {
                throw new Exception("Malformed EncryptedData");
            }
            p.setEncryptedContent(parts[1]);
        
            // Parse out the encrypted symmetric keys and add them to the Payload
            //
            String[] r = parts[0].Split(PAYLOAD_FIELD_DELIMITER, StringSplitOptions.None);
            String keyname = null;
            String encryptedkey = null;
            for (int i = 1; i < r.Length; i++) {
                if (r[i].StartsWith("KEYNAME:=")) {
                    keyname = r[i].Substring(9);
                    i++;
                    if (r[i].StartsWith("ENCRYPTEDKEY:=")) {
                        encryptedkey = r[i].Substring(14);
                        p.addReceivedReader(keyname, encryptedkey);
                    } else {
                        throw new Exception("Malformed EncryptedData - encrypted key value expected but not found");
                    }
                } else {
                    throw new Exception("Malformed EncryptedData - key name expected but not found");
                }
            }
        }

        /**
         * Parse the payloads in the given DistributionEnvelope and its manifest
         * 
         * @returns Array of Payload instances
         */ 
        public Payload[] getPayloads(DistributionEnvelope d)
        {
            StringWriter extractBuffer = new StringWriter();
            XmlTextWriter extractWriter = new XmlTextWriter(extractBuffer);
            StringReader sr = new StringReader(d.getEnvelope());
            XmlTextReader rdr = new XmlTextReader(sr);
            payloadExtractor.Transform(rdr, extractWriter);
            return splitPayloads(extractBuffer.GetStringBuilder().ToString());
        }

        private Payload[] splitPayloads(String s)
        {
            String id = null;
            String mt = null;
            String pid = null;
            String b64 = null;
            String cmpd = null;
            String enc = null;
            String pbdy = null;

            String[] parts = s.Split(PAYLOAD_DELIMITER, StringSplitOptions.RemoveEmptyEntries);
            Payload[] payloads = new Payload[parts.Length];
            int i = 0;
            foreach (String p in parts)
            {                
                String[] fields = p.Split(PAYLOAD_FIELD_DELIMITER, StringSplitOptions.RemoveEmptyEntries);
                foreach (String f in fields)
                {
                    String[] element = f.Split(EQUALS_DELIMITER, StringSplitOptions.None);
                    if (element[0].Equals("ID"))
                    {
                        id = element[1];
                        continue;
                    }
                    if (element[0].Equals("MIMETYPE"))
                    {
                        mt = element[1];
                        continue;
                    }
                    if (element[0].Equals("PROFILEID"))
                    {
                        if (element.Length == 2)
                        {
                            pid = element[1];
                        }
                        continue;
                    }
                    if (element[0].Equals("BASE64"))
                    {
                        if (element.Length == 2)
                        {
                            b64 = element[1];
                        }
                        else
                        {
                            b64 = "false";
                        }
                        continue;
                    }
                    if (element[0].Equals("COMPRESSED"))
                    {
                        if (element.Length == 2)
                        {
                            cmpd = element[1];
                        }
                        else
                        {
                            cmpd = "false";
                        }
                        continue;
                    }
                    if (element[0].Equals("ENCRYPTED"))
                    {
                        if (element.Length == 2)
                        {
                            enc = element[1];
                        }
                        else
                        {
                            enc = "false";
                        }
                        continue;
                    }
                    if (element[0].Equals("PAYLOADBODY"))
                    {
                        pbdy = element[1];
//                        pbdy = pbdy.Remove(pbdy.LastIndexOf(PAYLOAD_DELIMITER[0]));
                        continue;
                    }                
                }
                payloads[i] = new Payload(id, mt, pid, b64, cmpd, enc);
                payloads[i].setContent(pbdy);
                i++;
            }
            return payloads;
        }

        /**
         * Parse the DistributionEnvelope XML in the given string.
         */ 
        public DistributionEnvelope getDistributionEnvelope(String s)
        {
            if (initialException != null)
            {
                throw initialException;
            }
            StringWriter extractBuffer = new StringWriter();
            XmlTextWriter extractWriter = new XmlTextWriter(extractBuffer);
            StringReader sr = new StringReader(s);
            XmlTextReader rdr = new XmlTextReader(sr);
            distributionEnvelopeExtractor.Transform(rdr, extractWriter);
            return splitExtract(extractBuffer.GetStringBuilder().ToString());
        }

        /**
         * Parse the DistributionEnvelope XML read from the given Stream
         */ 
        public DistributionEnvelope getDistributionEnvelope(Stream s)
        {
            if (initialException != null)
            {
                throw initialException;
            }
            StringWriter extractBuffer = new StringWriter();
            XmlTextWriter extractWriter = new XmlTextWriter(extractBuffer);
            XmlTextReader rdr = new XmlTextReader(s);
            distributionEnvelopeExtractor.Transform(rdr, extractWriter);
            return splitExtract(extractBuffer.GetStringBuilder().ToString());
        }

        private DistributionEnvelope splitExtract(String s)
        {
            DistributionEnvelope d = new DistributionEnvelope();
            int ee = s.IndexOf(EXTRACT_END_DELIMITER);
            if (ee == -1)
            {
                throw new Exception("Failed DistributionEnvelope extract - envelope not found");
            }
            int ds = ee + EXTRACT_END_DELIMITER.Length;
            String env = s.Substring(ds);
            if ((env == null) || (env.Trim().Length == 0))
            {
                throw new Exception("Failed DistributionEnvelope extract - zero-length envelope");
            }
            d.setDistributionEnvelope(env);
            int es = s.IndexOf(EXTRACT_START_DELIMITER);
            if (es == -1)
            {
                throw new Exception("Failed DistributionEnvelope extract - extract not found");
            }
            es += EXTRACT_START_DELIMITER.Length;
            String extract = s.Substring(es, ee);

            Regex lineDelimiter = new Regex("\\!");
            Regex fieldDelimiter = new Regex("#");

            String[] lines = lineDelimiter.Split(extract);
            List<Address> addresses = new List<Address>();
            List<Identity> audit = new List<Identity>();

            foreach (String l in lines)
            {
                String[] fields = fieldDelimiter.Split(l);
                if (fields[0].Equals("R"))
                {
                    Address a = null;
                    if (fields.Length > 1)
                    {
                        a = (Address)makeEntity(true, fields);
                        d.setSender(a);
                    }
                    continue;
                }
                if (fields[0].Equals("S"))
                {
                    if (fields.Length == 2)
                    {
                        d.setService(fields[1]);
                    }
                    continue;
                }
                if (fields[0].Equals("T"))
                {
                    if (fields.Length == 2)
                    {
                        d.setTrackingId(fields[1]);
                    }
                    continue;
                }
                if (fields[0].Equals("A"))
                {
                    Address a = (Address)makeEntity(true, fields);
                    addresses.Add(a);
                    continue;
                }
                if (fields[0].Equals("I"))
                {
                    Identity i = (Identity)makeEntity(false, fields);
                    audit.Add(i);
                    continue;
                }
                if (fields[0].Equals("H"))
                {
                    if (fields.Length == 3)
                    {
                        d.addHandlingSpecification(fields[1], fields[2]);
                    }
                    else
                    {
                        d.addHandlingSpecification(fields[1], "");
                    }
                }
            }
            d.setTo(addresses.ToArray());
            d.setAudit(audit.ToArray());
            // Add any checkers we have for "all" and for this DE, also the adders and members
            // Dictionary<string,string[]> where key is service name, and array is list of class names
            if (checkClasses != null)
            {
                if (checkClasses.ContainsKey("all"))
                    makeCheckers(d, checkClasses["all"]);
                if (checkClasses.ContainsKey(d.getService()))
                    makeCheckers(d, checkClasses[d.getService()]);
            }
            return d;
        }

        private void makeCheckers(DistributionEnvelope d, List<string> cnames)
        {
            foreach (string s in cnames)
            {
                IDistributionEnvelopeChecker c = null;
                try
                {
                    c = makeChecker(s);
                }
                catch (Exception e)
                {
                    // Report any trouble and go on to the next one
                    EventLog logger = new EventLog("Application", ".", DistributionEnvelopeException.SYSTEM_LOGGER);
                    logger.WriteEntry("Failed to instantiate DistributionEnvelope checker class " + s + " : " + e.Message, EventLogEntryType.Error);
                    continue;
                }
                if (c == null)
                {
                    EventLog logger = new EventLog("Application", ".", DistributionEnvelopeException.SYSTEM_LOGGER);
                    logger.WriteEntry("Failed to instantiate DistributionEnvelope checker class " + s, EventLogEntryType.Error);
                }
                else
                {
                    d.addChecker(c);
                }
            }
        }

        private IDistributionEnvelopeChecker makeChecker(string s)
        {
            // s is a string specifying the class name, of the form "[Assembly:]Namespace.Class", where
            // if Assembly is omitted the assembly defaults to "DistributionEnvelopeTools", otherwise it contains the
            // name of the assembly where the class is located.
            //
            IDistributionEnvelopeChecker dec = null;
            string classname = s;
            string assemblyname = "DistributionEnvelopeTools";
            if (s.Contains(":"))
            {
                assemblyname = s.Substring(0, s.IndexOf(":"));
                classname = s.Substring(s.IndexOf(":") + 1);
            }
            Assembly a = Assembly.Load(new AssemblyName(assemblyname));
            dec = (IDistributionEnvelopeChecker)a.CreateInstance(classname);
            return dec;
        }

        private Entity makeEntity(bool addr, String[] f) 
        {
            Entity e = null;
            if (addr) {
                if (f[1].Length > 0) {
                    e = new Address(f[2], f[1]);
                } else {
                    e = new Address(f[2]);
                }            
            } else {
                if (f[1].Length > 0) {
                    e = new Identity(f[2], f[1]);
                } else {
                    e = new Identity(f[2]);
                }            
            }        
            return e;
        }

    }
}
