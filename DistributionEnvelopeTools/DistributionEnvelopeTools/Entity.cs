using System;
using System.Collections.Generic;
using System.Text;
/*
Copyright 2011 Damian Murphy <murff@warlock.org>

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
     * Abstract superclass for addressable entities: Identities and Addresses
     * from the DistributionEnvelope.
     */ 
    public abstract class Entity
    {
        /**
         * Return the parts of an entity as a List<String>. This
         * is intended to be used by routers and for ITK entities will
         * split on colons. Suitably overriden, any type of address can
         * be handled.
         */ 
        public abstract List<String> getParts();

        protected const int UNDEFINED_TYPE = -1;
        protected String uri = null;
        protected String stype = null;
        protected String oid = null;
        protected int type = UNDEFINED_TYPE;
        protected bool routable = false;

        /**
         * Default implementation of a URI splitter working on
         * colons as part delimiters.
         */ 
        protected List<String> splitUri(String s)
        {
            String[] p = s.Split(':');
            List<String> a = new List<String>();
            foreach (String e in p) {
                a.Add(e);
            }
            return a;
        }

        public String getUri() { return uri; }
        public String getOID() { return oid; }
        public String getDisplayType() { return stype; }
        public int getType() { return type; }
        public bool isRoutable() { return routable; }
    }
}
