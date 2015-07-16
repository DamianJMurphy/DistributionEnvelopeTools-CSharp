using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Reflection;
using System.Text;

namespace DistributionEnvelopeTools
{
    /**
     * Subclass of DistributionEnvelope for making Infrastructure Acknowledgments.
     */
    public class AckDistributionEnvelope : DistributionEnvelope
    {
        public const String SERVICE = "urn:nhs-itk:ns:201005:InfrastructureAcknowledgment"; 
        protected const String TIMESTAMP = "yyyy-MM-dd'T'hh:mm:ss";
        protected String serviceRef = null;
    
        /** Property name for the router's identity, declared in acks and nacks */
        protected const String AUDIT_ID_PROPERTY = "org.warlock.itk.router.auditidentity";
        /** Property name for the router's address */
        protected const String SENDER_PROPERTY = "org.warlock.itk.router.senderaddress";
        private const String ACK_TEMPLATE = "infrastructure_ack_template.xml.txt";

        /**
         * Construct the AckDistributionEnvelope as an acknowledgment to the given
         * DistributionEnvelope.
         */ 
        public AckDistributionEnvelope(DistributionEnvelope d) : base()
        {
            Address[] a = new Address[1];
            a[0] = d.getSender();
            setTo(a);
            String id = null;
            String snd = null;
            try
            {
                Configuration config = ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None);
                id = config.AppSettings.Settings[AUDIT_ID_PROPERTY].Value;
                snd = config.AppSettings.Settings[SENDER_PROPERTY].Value;
            }
            catch (Exception e)
            {
                throw new DistributionEnvelopeException("SYST-0000", "Configuration manager exception", e.ToString());
            }
            Address sndr = new Address(snd);
            Identity[] auditId = new Identity[1];
            auditId[0] = new Identity(id);
            setAudit(auditId);
            setSender(sndr);
            setService(SERVICE);
            setTrackingId(d.getTrackingId());
            serviceRef = d.getService();
        }

        /** Construct acknowledgment message.
         * 
         * @throws DistributionEnvelopeException if construction fails.
         */
        public virtual void makeMessage()
        {
            Assembly assembly = Assembly.GetExecutingAssembly();
            StreamReader sr = new StreamReader(assembly.GetManifestResourceStream(ACK_TEMPLATE));
            StringBuilder sb = initContent(sr);
            setDistributionEnvelope(sb.ToString());
        }
    
        /** This method constructs the distribution envelope and such content from
         * the generic infrastructure ack as is common to both acks and nacks. It
         * returns a StringBuilder to that the nack subclass can perform its own
         * substitutions.
         * 
         * @param is an InputStream carrying the infrastructure ack or nack, typically
         * read from the jarfile
         * @return a StringBuilder containing the substituted template.
         * @throws DistributionEnvelopeException 
         */
        protected StringBuilder initContent(TextReader rdr) 
        {
            StringBuilder sb = new StringBuilder();
            String line = null;
            try {
                while((line = rdr.ReadLine()) != null) {
                    sb.Append(line);
                    sb.Append("\r\n");
                }
            }
            catch(Exception e) {
                throw new DistributionEnvelopeException("SYST-0001", "Failed to read ACK template", e.ToString());
            }
            sb.Replace("__TRACKING_ID__", System.Guid.NewGuid().ToString().ToUpper());
            sb.Replace("__PAYLOAD_ID__", System.Guid.NewGuid().ToString().ToUpper());
            sb.Replace("__SERVICE_REF__", serviceRef);
            sb.Replace("__TIMESTAMP__", DateTime.Now.ToString(TIMESTAMP));
            sb.Replace("__SERVICE__", getService());
            sb.Replace("__TRACKING_ID_REF__", getTrackingId());
            sb.Replace("__AUDIT_ID__", identities[0].getUri());
            String to_oid = recipients[0].getOID();
            if (to_oid.Equals("2.16.840.1.113883.2.1.3.2.4.18.22")) {
                sb.Replace("__TO_OID__", "");
            } else {
                sb.Replace("__TO_OID__", " type=\"__EXPLICIT_OID__\" ");
                sb.Replace("__EXPLICIT_OID__", to_oid);
            }
            sb.Replace("__TO_URI__", recipients[0].getUri());
            sb.Replace("__SENDER__", sender.getUri());
            return sb;
        }
    }
}
