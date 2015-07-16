using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
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
     * Class representing an ITK DistributionEnvelope. This can both be
     * built by a sender, or produced (typically by the DistributionEnvelopeHelper class)
     * by parsing a received ITK message.
     */
    public class DistributionEnvelope
    {
        public const String INTERACTIONID = "urn:nhs-itk:ns:201005:interaction";
        protected String envelope = null;
        protected String service = null;
        protected String trackingId = null;
        protected String interactionId = null;
        protected Address sender = null;

        protected Dictionary<string, string> handlingSpecification = null;
        protected List<Payload> payloads = null;
        protected List<Address> recipients = null;
        protected List<Identity> identities = null;

        protected List<IDistributionEnvelopeChecker> checkers = null;
        protected List<string>checkerFailures = null;

        protected String itkNamespacePrefix = "itk";

        /**
         * Called by the DistributionEnvelopeHelper and the static newInstance()
         * method.
         */ 
        internal DistributionEnvelope()
        {
            recipients = new List<Address>();
            identities = new List<Identity>();
        }

        /**
         * Add a distribution envelope checker to the list.
         */ 
        public void addChecker(IDistributionEnvelopeChecker c)
        {
            if (checkers == null)
                checkers = new List<IDistributionEnvelopeChecker>();
            checkers.Add(c);
        }

        /**
         * Run any checks we have, return true if all pass, otherwise return false
         * and set failure descriptions in checkerFailures otherwise.
         */
        public bool doChecks(object o)
        {
            bool passed = true;
            if (checkers == null)
                return true;
            foreach (IDistributionEnvelopeChecker c in checkers)
            {
                if (!c.check(this, o))
                {
                    passed = false;
                    if (checkerFailures == null)
                        checkerFailures = new List<string>();
                    checkerFailures.Add(c.getDescription());
                }
            }
            return passed;
        }

        /**
         * Retrieve any check failures we have.
         */ 
        public string getCheckFailures()
        {
            if (checkerFailures == null)
                return "";
            StringBuilder sb = new StringBuilder("Check failures for distribution envelope: ");
            sb.Append(trackingId);
            sb.Append("\r\n");
            foreach (string s in checkerFailures)
            {
                sb.Append(s);
                sb.Append("\r\n");
            }
            return sb.ToString();
        }

        /**
         * Convenience method for creating and doing basic initialisation on a
         * DistributionEnvelope instance, for use by senders.
         */ 
        public static DistributionEnvelope newInstance()
        {
            DistributionEnvelope d = new DistributionEnvelope();
            d.setTrackingId("uuid_" + System.Guid.NewGuid().ToString().ToLower());
            return d;
        }

        /**
         * When the DistributionEnvelope is serialised, by default it will use the
         * prefix "itk" for those nodes in the ITK namespace. If a sender has a
         * need for some other prefix to be used, it should be set here.
         * 
         * @param p The prefix to be used.
         */ 
        public void setITKNamespacePrefix(String p)
        {
            if ((p != null) && (p.Trim().Length != 0))
            {
                itkNamespacePrefix = p;
            }
        }

        /**
         * Called by the DistributionEnvelopeHelper to set the recipients list
         * after it has been parsed out of the received DistributionEnvelope
         * XML.
         * 
         * @param t[] Address instances.
         */ 
        internal void setTo(Address[] t)
        {
            if (t == null)
            {
                return;
            }
            for (int i = 0; i < t.Length; i++)
            {
                recipients.Add(t[i]);
            }
        }

        /**
         * Called by the DistributionEnvelopeHelper to set the audit identity list
         * after it has been parsed out of the received DistributionEnvelope
         * XML.
         * 
         * @param t[] Audit Identity instances.
         */ 
        internal void setAudit(Identity[] id)
        {
            if (id == null)
            {
                return;
            }
            for (int i = 0; i < id.Length; i++)
            {
                identities.Add(id[i]);
            }
        }

        /**
         * Called by the DistributionEnvelopeHelper to set the sender address
         * after it has been parsed out of the received DistributionEnvelope
         * XML.
         * 
         * @param t Sender Address.
         */ 
        internal void setSender(Address a) { sender = a; }

        /**
         * Called by the DistributionEnvelopeHelper to set the text of the
         * received DistributionEnvelope XML after other data have been parsed 
         * out.
         * 
         * @param d DistributionEnvelope XML as a string
         */ 
        internal void setDistributionEnvelope(String d) { envelope = d; }

        /**
         * Called by the DistributionEnvelopeHelper to set the tracking id
         * of a received DistributionEnvelope.
         */
        internal void setTrackingId(String t) { trackingId = t; }

        /**
         * Called by the DistributionEnvelopeHelper to set the service
         * of a received DistributionEnvelope, or by a builder to set
         * the service attribute.
         */        
        public void setService(String s) { service = s; }

        /**
         * Adds a handling specification given the type and value. This does
         * not validate that the given type is defined in the ITK specifications.
         * Sets the "interactionId" if the supplied type is the identifier
         * for an ITK interactionId.
         */ 
        public void addHandlingSpecification(String s, String v)
        {
            if (handlingSpecification == null)
            {
                handlingSpecification = new Dictionary<String, String>();
            }
            handlingSpecification.Add(s, v);
            if (s.Equals(INTERACTIONID))
            {
                interactionId = v;
            }
        }

        /**
         * @returns The XML text of the DistributionEnvelope.
         */ 
        public String getEnvelope() { return envelope; }

        /**
         * @returns the serviceId 
         */
        public String getService() { return service; }

        /**
         * @returns the trackingId
         */ 
        public String getTrackingId() { return trackingId; }

        /**
         * @returns the interactionId (note that this MAY be null, and it is not
         * an error for a DistributionEnvelope to have no interactionId, so 
         * applications which require interactionId are responsible for checking
         * for null returns from this method.
         */ 
        public String getInteractionId() { return interactionId; }

        /**
         * @returns Array of recipient Address objects, may be empty or null.
         */ 
        public Address[] getTo() { 
            return recipients.ToArray(); 
        }
    
        /**
         * @returns Array of author audit Identity objects. May be empty or null.
         */ 
        public Identity[] getAudit() { 
            return identities.ToArray(); 
        }
    
        /**
         * @returns Sender Address object. May be null.
         */
        public Address getSender() { return sender; }
    
        /**
         * Used by senders to add recipient addresses. Any address type may
         * be entered, described by the appropriate OID. Where the OID is
         * null, the default "ITK address" is supplied.
         * 
         * @param oid OID for the address type, or null
         * @param id Address 
         */ 
        public void addRecipient(String oid, String id) 
        {
            Address a = null;
            if (oid == null) {
                a = new Address(id);
            } else {
                a = new Address(id, oid);
            }
            recipients.Add(a);
        }

        /**
        * Used by senders to add sender identities. Any identity type may
        * be entered, described by the appropriate OID. Where the OID is
        * null, the default "ITK identity" is supplied.
        * 
        * @param oid OID for the identity type, or null
        * @param id Address 
        */    
        public void addIdentity(String oid, String id)
        {
            Identity ident = null;
            if (oid == null) {
                ident = new Identity(id);
            } else {
                ident = new Identity(id, oid);
            }
            identities.Add(ident);
        }

        /**
         * (This should probably be called setSender()) Used by the
         * sender to set the sender address. Any address type may
         * be entered, described by the appropriate OID. Where the OID is
         * null, the default "ITK address" is supplied.
         * 
         * @param oid OID for the address type, or null
         * @param id Address 
         */
        public void addSender(String oid, String id) 
        {
            Address a = null;
            if (oid == null) {
                a = new Address(id);
            } else {
                a = new Address(oid, id);
            }
            sender = a;
        }
    
        /**
         * Called by the sender to set the ITK interaction id. This
         * sets the appropriate handlingSpecification. The supplied
         * value is NOT validated against any list of known, defined
         * ITK interaction ids.
         * 
         * @param id Interaction id.
         */ 
        public void setInteractionId(String id) {
            addHandlingSpecification(INTERACTIONID, id);
        }
    
        /**
         *  Adds a pre-build Payload instance.
         */ 
        public void addPayload(Payload p) {
            if (payloads == null){
                payloads = new List<Payload>();
            }
            payloads.Add(p);
        }

        /**
         * When the DistributionEnvelopeHelper is used to construct a DistributionEnvelope
         * from a received message, it does not parse the payloads themselves. So the
         * DistributionEnvelope instance contains no Payload objects. If these are required,
         * the parsePayloads() method is called to parse out the payloads from the received
         * XML.
         */ 
        public void parsePayloads()
        {
            DistributionEnvelopeHelper helper = DistributionEnvelopeHelper.getInstance();
            Payload[] plds = helper.getPayloads(this);
            foreach (Payload p in plds) {
                addPayload(p);
            }
        }
    
        /**
         * Convenience method called by a sender to explicitly set the "ack requested" handling
         * specification.
         */ 
        public void setAckRequested(bool b)
        {
            if (b)
            {
                addHandlingSpecification("urn:nhs-itk:ns:201005:ackrequested", "true");
            }
            else
            {
                addHandlingSpecification("urn:nhs-itk:ns:201005:ackrequested", "false");
            }
        }

        /**
         * @param key URI of the requested handling specification
         * @returns Value, or null if that handling specification is not set.
         */ 
        public String getHandlingSpecification(String key)
        {
            if (handlingSpecification == null)
            {
                return null;
            }
            String v = null;
            if (handlingSpecification.TryGetValue(key, out v))
            {
                return v;
            }
            return null;
        }

        /**
         * Serialise to XML on the given TextWriter. 
         */
        public void write(TextWriter w)
        {
            if (service == null)
            {
                throw new Exception("No service");
            }
            if ((payloads == null) || (payloads.Count == 0)) 
            {
                throw new Exception("No payloads");
            }
            w.Write("<");
            w.Write(itkNamespacePrefix);
            w.Write(":DistributionEnvelope xmlns:");
            w.Write(itkNamespacePrefix);
            w.Write("=\"urn:nhs-itk:ns:201005\"><");
            w.Write(itkNamespacePrefix);
            w.Write(":header service=\"");
            w.Write(service); 
            w.Write("\" trackingid=\"");
            w.Write(trackingId);
            w.Write("\">");
            if (!(recipients.Count == 0)) {
                w.Write("<");
                w.Write(itkNamespacePrefix);
                w.Write(":addresslist>");
                foreach (Address a in recipients) {
                    w.Write("<");
                    w.Write(itkNamespacePrefix);
                    w.Write(":address");
                    if (a.getOID() != null) {
                        w.Write(" type=\"");
                        w.Write(a.getOID());
                        w.Write("\"");
                    }
                    w.Write(" uri=\"");
                    w.Write(a.getUri());
                    w.Write("\"/>");
                }
                w.Write("</");
                w.Write(itkNamespacePrefix);
                w.Write(":addresslist>");
            }
            if (!(identities.Count == 0)) {
                w.Write("<");
                w.Write(itkNamespacePrefix);
                w.Write(":auditIdentity>");
                foreach (Identity a in identities) {
                    w.Write("<");
                    w.Write(itkNamespacePrefix);
                    w.Write(":id");
                    if (a.getOID() != null) {
                        w.Write(" type=\"");
                        w.Write(a.getOID());
                        w.Write("\"");
                    }
                    w.Write(" uri=\"");
                    w.Write(a.getUri());
                    w.Write("\"/>");
                }
                w.Write("</");
                w.Write(itkNamespacePrefix);
                w.Write(":auditIdentity>");            
            }
           w.Write("<");
           w.Write(itkNamespacePrefix);
           w.Write(":manifest count=\"");
           w.Write(payloads.Count);
           w.Write("\">");
           foreach (Payload p in payloads) {
               w.Write(p.makeManifestItem(itkNamespacePrefix));
           }
           w.Write("</");
           w.Write(itkNamespacePrefix);
           w.Write(":manifest>");
           if (sender != null) {
                w.Write("<");
                w.Write(itkNamespacePrefix);
                w.Write(":senderAddress");
                if (sender.getOID() != null) {
                    w.Write(" type=\"");
                    w.Write(sender.getOID());
                    w.Write("\"");
                }
                w.Write(" uri=\"");
                w.Write(sender.getUri());
                w.Write("\"/>");          
           }
           if ((handlingSpecification != null) && !(handlingSpecification.Count == 0)){
                w.Write("<");
                w.Write(itkNamespacePrefix);
                w.Write(":handlingSpecification>");
                foreach (String k in handlingSpecification.Keys) {
                    w.Write("<");
                    w.Write(itkNamespacePrefix);
                    w.Write(":spec key=\"");
                    w.Write(k);
                    w.Write("\" value=\"");
                    String v = null;
                    if (handlingSpecification.TryGetValue(k, out v)) 
                    {
                        w.Write(v);
                    }
                    w.Write("\"/>");
                }
                w.Write("</");
                w.Write(itkNamespacePrefix);
                w.Write(":handlingSpecification>");
           }
           w.Write("</");
           w.Write(itkNamespacePrefix);
           w.Write(":header><");
           w.Write(itkNamespacePrefix);
           w.Write(":payloads count=\"");
           w.Write(payloads.Count);
           w.Write("\">");
           foreach (Payload p in payloads) {
               w.Write("<");
               w.Write(itkNamespacePrefix);
               w.Write(":payload id=\"");
               w.Write(p.getManifestId());
               w.Write("\">");
               w.Write(p.getBody());
               w.Write("</");
               w.Write(itkNamespacePrefix);
               w.Write(":payload>");
           }
           w.Write("</");
           w.Write(itkNamespacePrefix);
           w.Write(":payloads></");
           w.Write(itkNamespacePrefix);
           w.Write(":DistributionEnvelope>");
        }

        /**
         * Calls write() and returns the serialised XML as a string.
         */
        public override String ToString()
        {
            StringWriter sw = new StringWriter();
            try
            {
                write(sw);
            }
            catch (Exception e)
            {
                // Note: When running in a debugger, ToString() will be called lots by the debugger so will
                // typically result in a lot of Application log entries as write() finds things it doesn't
                // like. There are two ways to respond to that:
                //
                // 1. Live with it, or
                // 2. Use something like System.Diagnostics.Debugger to determine whether actually
                //      to report something.
                //
                // As annoying as spurious Application event log entries are, "live with it" is a safer option
                // to avoid suppressing log entries we actually want to see.
                //
                EventLog logger = new EventLog("Application", ".", DistributionEnvelopeException.SYSTEM_LOGGER);
                logger.WriteEntry("Exception serialising DistributionEnvelope: " + e.ToString(), EventLogEntryType.Error);
            }
            return sw.ToString();
        }

        // Future: Need to be configured for ackable services from the
        // properties. For now, just say we don't ack InfAck/InfNack and ignore
        // that we don't ack "broadcast" either. This is intended mainly for
        // use by routers or infrastructure receivers.
        //
        public bool isAckable() {
            if (service.Equals(AckDistributionEnvelope.SERVICE)) {
                return false;
            }
            if (service.Contains("Broadcast")) {
                return false;
            }
            return true;
        }
    
        /**
         * @returns the <i>i</i>th payload, or null if it does not exist
         */ 
        public String getPayloadId(int i)
        {
            if (i >= payloads.Count)
            {
                return null;
            }
            return payloads[i].getManifestId();
        }
    }
}
