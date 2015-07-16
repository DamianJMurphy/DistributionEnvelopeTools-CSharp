using System;
using System.IO;
using System.Reflection;
using System.Text;

namespace DistributionEnvelopeTools
{
    /**
     * Subclass of DistributionEnvelope for making Infrastructure Negative
     * Acknowledgments.
     */
    public class NackDistributionEnvelope : AckDistributionEnvelope
    {
        private const String NACK_TEMPLATE = "infrastructure_nack_template.xml.txt";
        private DistributionEnvelopeException ex = null;

        /**
         * Construct the NackDistributionEnvelope as an acknowledgment to the given
         * DistributionEnvelope, failing because of the given exception.
         */ 
        public NackDistributionEnvelope(DistributionEnvelope d, DistributionEnvelopeException e)
            : base(d)
        {
            ex = e;
        }

        public override void makeMessage()
        {
            Assembly assembly = Assembly.GetExecutingAssembly();
            StreamReader sr = new StreamReader(assembly.GetManifestResourceStream(NACK_TEMPLATE));
            StringBuilder sb = initContent(sr);

            sb.Replace("__ERROR_ID__", ex.getId());
            sb.Replace("__ERROR_CODE__", ex.getCode());
            sb.Replace("__ERROR_TEXT__", ex.getText());
            if (ex.getDiagnostics() == null)
            {
                sb.Replace("__ERROR_DIAGNOSTICS__", "");
            }
            else
            {
                sb.Replace("__ERROR_DIAGNOSTICS__", "<itk:ErrorDiagnosticText><![CDATA[__ERR_DIAG_REWRITE__]]></itk:ErrorDiagnosticText>");
                sb.Replace("__ERR_DIAG_REWRITE__", ex.getDiagnostics());
            }
            setDistributionEnvelope(sb.ToString());
        }
    }
}
