using System;
using System.Collections.Generic;
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
     * Object representation of a identity in a Distribution
     * Envelope. This class can hold any URI identity type, identified by OID. It 
     * defaults to the ITK address, and also "knows" DTS mailbox, the Spine identifiers
     * UID, URP, Organisation (ODS code) and ASID.
     * Identities cannot be empty or null.
     */ 
    public class Identity : Entity
    {
        public const int ITK_IDENTITY = 10000;
    
        public const String ITK_IDENTITY_PREFIX = "urn:nhs-uk:identity:";   
        public const int IDENTITY_PREFIX_LENGTH = 20;

        private static int[] TYPES = {10000, 10001, 10002, 10003, 10004};
        private static String[] DISPLAYTYPES = {"ITK identity (explicit)", "DTS mailbox", "Spine UID", "Spine URP", "Spine ORG", "Spine ASID"};
        private static String[] OIDS = {"2.16.840.1.113883.2.1.3.2.4.18.27",
                                                "2.16.1.113883.2.1.3.2.4.21.1",
                                                "1.2.826.0.1285.0.2.0.65",
                                                "1.2.826.0.1285.0.2.0.67",
                                                "1.2.826.0.1285.0.2.0.109",
                                                "1.2.826.0.1285.0.2.0.107"};
    
        private bool external = false;

        /**
         * Constructs an ITK identitu with the given URI.
         * 
         * @param u URI ITK identity
         */ 
        public Identity(String u) 
        {
            if ((u == null) || (u.Trim().Length == 0)) {
                throw new DistributionEnvelopeException("ADDR-0003", "Invalid identity: null or empty", null);
            }
            type = ITK_IDENTITY;
            stype = "ITK identity (implicit)";
            uri = u;
            oid = OIDS[0];
            routable = true;
        }

        /**
         * Constructs any URI identity with the given URI, and type identified by the
         * given OID.
         * 
         * @param u URI identity in form appropriate to the given OID
         * @param o OID for the identity type
         */ 
        public Identity(String u, String o) 
        {
            if ((o == null) || (o.Trim().Length == 0)) {
                throw new DistributionEnvelopeException("ADDR-0004", "Error in identity: null or empty OID for identity: " + u, null);
            }
            if ((u == null) || (u.Trim().Length == 0)) {
                throw new DistributionEnvelopeException("ADDR-0003", "Invalid identity: null or empty", null);
            }
            oid = o;
            int i = -1;
            for (i = 0; i < OIDS.Length; i++) {
                if (OIDS[i].Equals(o)) {
                    type = i;
                    stype = DISPLAYTYPES[i];
                    uri = u;
                    external = true;
                    routable = (type == ITK_IDENTITY);
                    return;
                }
            }
        }

        public bool isExternal() { return external; }
    
        override public List<String> getParts() {
            String s = uri.Substring(IDENTITY_PREFIX_LENGTH);
            return splitUri(s);    
        }

    }
}
