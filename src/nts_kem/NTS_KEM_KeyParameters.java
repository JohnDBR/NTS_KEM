package nts_kem;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;


public class NTS_KEM_KeyParameters
    extends AsymmetricKeyParameter
{
    private NTS_KEM_Parameters params;

    public NTS_KEM_KeyParameters(
        boolean isPrivate,
        NTS_KEM_Parameters params)
    {
        super(isPrivate);
        this.params = params;
    }


    public NTS_KEM_Parameters getParameters()
    {
        return params;
    }

}
