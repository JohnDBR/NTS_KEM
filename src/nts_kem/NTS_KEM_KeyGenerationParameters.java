package nts_kem;

import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;

public class NTS_KEM_KeyGenerationParameters
    extends KeyGenerationParameters
{
    private NTS_KEM_Parameters params;

    public NTS_KEM_KeyGenerationParameters(
        SecureRandom random,
        NTS_KEM_Parameters params)
    {
        // XXX key size?
        super(random, 256);
        this.params = params;
    }

    public NTS_KEM_Parameters getParameters()
    {
        return params;
    }
}
