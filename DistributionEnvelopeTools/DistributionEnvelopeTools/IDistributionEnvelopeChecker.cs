using System;

namespace DistributionEnvelopeTools
{
    public interface IDistributionEnvelopeChecker
    {
        bool check(DistributionEnvelope d, object o);
        string getDescription();
    }
}
