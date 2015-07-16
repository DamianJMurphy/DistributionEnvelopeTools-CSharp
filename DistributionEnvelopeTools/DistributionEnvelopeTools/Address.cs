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
     * Object representation of a recipient or sender address in a Distribution
     * Envelope. This class can hold any URI address type, identified by OID. It 
     * defaults to the ITK address, and also "knows" DTS mailbox and Spine ASID
     * types. Addresses cannot be empty or null.
     */ 
    public class Address : Entity
    {
        public const int ITK_ADDRESS = 1000;
        public const String ITK_ADDRESS_PREFIX = "urn:nhs-uk:addressing:";
        public const int ADDRESS_PREFIX_LENGTH = 22;

        // Some known OIDs. Right now there are only three of these supported:
        // ITK, DTS and Spine ASID. So they're given here. For extensibility 
        // they should be read from somewhere - probably a tab-delimited file
        // shipped in the JAR would be flexible enough... 
    
        private int[] TYPES = {1000, 1001, 1002};
        private String[] DISPLAYTYPES = {"ITK address (explicit)", "DTS mailbox", "Spine ASID"};
        private String[] OIDS = {"2.16.840.1.113883.2.1.3.2.4.18.22",
                                                "2.16.1.113883.2.1.3.2.4.21.1",
                                                "1.2.826.0.1285.0.2.0.107"};
 
        /**
         * Constructs an ITK address with the given URI.
         * 
         * @param u URI ITK address
         */ 
        public Address(String u) 
        {
            if ((u == null) || (u.Trim().Length == 0)) {
                throw new DistributionEnvelopeException("ADDR-0001", "Invalid address: null or empty", null);
            }
            type = ITK_ADDRESS;
            stype = "ITK address (implicit)";
            uri = u;
            oid = OIDS[0];
            routable = true;
        }
        
        /**
         * Constructs any URI address with the given URI, and type identified by the
         * given OID.
         * 
         * @param u URI address in form appropriate to the given OID
         * @param o OID for the address type
         */ 
        public Address(String u, String o)
        {

            if ((o == null) || (o.Trim().Length == 0))
            {
                throw new DistributionEnvelopeException("ADDR-0002", "Error in address: null or empty OID for address: " + u, null);
            }
            if ((u == null) || (u.Trim().Length == 0))
            {
                throw new DistributionEnvelopeException("ADDR-0001", "Invalid address: null or empty", null);
            }
            int i = -1;
            oid = o;
            for (i = 0; i < OIDS.Length; i++)
            {
                if (OIDS[i].Equals(o))
                {
                    type = i;
                    stype = DISPLAYTYPES[i];
                    uri = u;
                    routable = true;
                    return;
                }
            }
            throw new DistributionEnvelopeException("ADDR-0005", "Unrecognised OID", o + " for address: " + u);
        }

        override public List<String> getParts()
        {
            String s = uri.Substring(ADDRESS_PREFIX_LENGTH);
            return splitUri(s);
        }
    }
}