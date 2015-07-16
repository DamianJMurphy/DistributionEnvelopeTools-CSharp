using System;
using System.Diagnostics;
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
     * DistributionEnvelope exception class. This is the .Net port which
     * logs errors through the Windows "Application" log.
     */ 
    public class DistributionEnvelopeException : Exception
    {
        public const String SYSTEM_LOGGER = "DISTRIBUTION_ENVELOPE_TOOLS_LOG";

        public const int ERROR = 0;
        public const int FAILUREAUDIT = 1;
        public const int INFORMATION = 2;
        public const int SUCCESS = 3;
        public const int WARNING = 4;

        private String id = null;
        private String code = null;
        private String text = null;
        private StringBuilder diagnostics = null;
        private String applicationContext = null;
        private String messageId = null;
        private String sender = null;

        private int loggingLevel = 0;
        private bool stackTrace = true;

        public DistributionEnvelopeException(String c, String t, String d)
        {
            Guid g = Guid.NewGuid();
            id = g.ToString().ToUpper();
            code = c;
            text = t;
            if (d != null)
            {
                diagnostics = new StringBuilder(d);
            }
        }

        /** Add context information and log the error. Any can be null.
         * 
         * @param n Application context
         * @param m Tracking id
         * @param s Sender 
         */
        public void recordContext(String n, String m, String s) { 
            applicationContext = n; 
            messageId = m;
            sender = s;
            log();
        }

        /**
         * Set the logging level for reporting this ITKException, if the default
         * java.util.logging.Level.WARNING is not what is wanted. Note that this
         * does NOT filter java.util.logging.Level.OFF so it assumes the caller 
         * knows what they are doing.
         * 
         * @param l Level to set logging
         */
        public void setLoggingLevel(int l) { loggingLevel = l; }
    
        /** Add context information and log the error. Any can be null.
         * 
         * @param s Sender 
         */    
        public void report(String s) {
            sender = s;
            log();
        }
    
        /** Make a detailed error report for logging.
         * 
         * @return Error report 
         */

        override public String ToString() {
            StringBuilder sb = new StringBuilder();
        
            sb.Append("ITKException\n");
            sb.Append("ID:\t");
            sb.Append(id);
            sb.Append("\nCode:\t");
            sb.Append(code);
            sb.Append("\nText:\t");
            sb.Append(text);
            sb.Append("\nDiagnostics:\n");
            sb.Append(diagnostics.ToString());
            if (applicationContext == null) {
                sb.Append("\nApplicationContext: Not set");
            } else {
                sb.Append("\nApplicationContext: ");
                sb.Append(applicationContext);
            }
            if (messageId == null) {
                sb.Append("\nTransmission id: Not set");
            } else {
                sb.Append("\nTransmission id: ");
                sb.Append(messageId);
            }
            if (sender == null) {
                sb.Append("\nSender: Not set");
            } else {
                sb.Append("\nSender: ");
                sb.Append(sender);
            }
            if (stackTrace) {
                sb.Append("\n\nStack Trace:\n");
                sb.Append(this.StackTrace);
                sb.Append(" at ");
                sb.Append(this.TargetSite);
            }
            return sb.ToString();
        }

        /** Turn off stack tracing in logs, for this exception. This is used for
         * "non error" conditions such as "blocking" routes, where there is a need
         * to nack the message, but where no actual error has occurred and the 
         * ITKException hasn't actually been thrown, so a stack
         * trace is inappropriate.
         * 
         */
        public void noStackTrace() { stackTrace = false; }

        public String getId() { return id; }
        public String getCode() { return code; }
        public String getText() { return text; }
        public String getDiagnostics() { return diagnostics.ToString(); }
    
        /** Append a comma, then some text, to the diagnostics.
         * 
         * @param s text to append 
         */
        public void updateDiagnostics(String s) {
            diagnostics.Append(", ");
            diagnostics.Append(s);
        }
    
        private void log() {
            
            String lname = (applicationContext == null) ? SYSTEM_LOGGER : applicationContext;
            if (!EventLog.SourceExists(lname))
            {
                EventLog.CreateEventSource(lname, "Application");
            }
            EventLogEntryType type = EventLogEntryType.Error;
            switch (loggingLevel) {
                case FAILUREAUDIT:
                    type = EventLogEntryType.FailureAudit;
                    break;
                case INFORMATION:
                    type = EventLogEntryType.Information;
                    break;
                case SUCCESS:
                    type = EventLogEntryType.SuccessAudit;
                    break;
                case WARNING:
                    type = EventLogEntryType.Warning;
                    break;

            }
            EventLog logger = new EventLog("Application", ".", lname);
            logger.WriteEntry(this.ToString(),type);
        }
    }
}
