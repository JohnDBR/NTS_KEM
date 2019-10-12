package nts_kem;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/**
 *
 * @author maxim
 */
public class NTS_KEM_KeyParameters
    extends AsymmetricKeyParameter
{
    private NTS_KEM_Parameters params;

    /**
     *
     * @param isPrivate
     * @param params
     */
    public NTS_KEM_KeyParameters(
        boolean isPrivate,
        NTS_KEM_Parameters params)
    {
        super(isPrivate);
        this.params = params;
    }

    /**
     *
     * @return
     */
    public NTS_KEM_Parameters getParameters()
    {
        return params;
    }

}
