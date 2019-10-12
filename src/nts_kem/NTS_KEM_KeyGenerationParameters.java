package nts_kem;

import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 *
 * @author maxim
 */
public class NTS_KEM_KeyGenerationParameters
    extends KeyGenerationParameters
{
    private NTS_KEM_Parameters params;

    /**
     *
     * @param random
     * @param params
     */
    public NTS_KEM_KeyGenerationParameters(
        SecureRandom random,
        NTS_KEM_Parameters params)
    {
        // XXX key size?
        super(random, 256);
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
