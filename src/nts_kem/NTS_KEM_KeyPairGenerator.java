package nts_kem;

import java.security.SecureRandom;
import java.util.Random;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.pqc.math.linearalgebra.GF2Matrix;
import org.bouncycastle.pqc.math.linearalgebra.GF2mField;
import pqc.math.linearalgebra.GoppaCode;
import pqc.math.linearalgebra.PermutationCustom;
import org.bouncycastle.pqc.math.linearalgebra.PolynomialGF2mSmallM;
import org.bouncycastle.pqc.math.linearalgebra.PolynomialRingGF2m;
import pqc.math.linearalgebra.GF2MatrixUtils;
import pqc.math.linearalgebra.GoppaCode.HCheck;


/**
 * This class implements key pair generation of the NTS_KEM Public Key
 * Cryptosystem (NTS_KEM_PKC).
 */
public class NTS_KEM_KeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{

    /**
     *
     */
    public NTS_KEM_KeyPairGenerator()
    {

    }


    /**
     * The OID of the algorithm.
     */
    private static final String OID = "1.3.6.1.4.1.8301.3.1.3.4.1";

    private NTS_KEM_KeyGenerationParameters NTS_KEM_Params;

    // the extension degree of the finite field GF(2^m)
    private int m;

    // the length of the code
    private int n;

    // the error correction capability
    private int t;
    
    // length of the key to be encapsulated
    private int l;

    // the field polynomial
    private int fieldPoly;

    // the source of randomness
    private SecureRandom random;

    // flag indicating whether the key pair generator has been initialized
    private boolean initialized = false;


    /**
     * Default initialization of the key pair generator.
     */
    private void initializeDefault()
    {
        NTS_KEM_KeyGenerationParameters mcParams = 
                new NTS_KEM_KeyGenerationParameters(CryptoServicesRegistrar.
                        getSecureRandom(), new NTS_KEM_Parameters());
        initialize(mcParams);
    }

    private void initialize(
        KeyGenerationParameters param)
    {
        this.NTS_KEM_Params = (NTS_KEM_KeyGenerationParameters)param;

        // set source of randomness
        this.random = param.getRandom();
        if (this.random == null)
        {
            this.random = CryptoServicesRegistrar.getSecureRandom();
        }

        this.m = this.NTS_KEM_Params.getParameters().getM();
        this.n = this.NTS_KEM_Params.getParameters().getN();
        this.t = this.NTS_KEM_Params.getParameters().getT();
        this.l = this.NTS_KEM_Params.getParameters().getL();
        this.fieldPoly = this.NTS_KEM_Params.getParameters().getFieldPoly();
        this.initialized = true;
    }


    private AsymmetricCipherKeyPair genKeyPair()
    {

        if (!initialized)
        {
            initializeDefault();
        }

        // finite field GF(2^m)
        GF2mField field = new GF2mField(m, fieldPoly);

        // irreducible Goppa polynomial 
        PolynomialGF2mSmallM gp = new PolynomialGF2mSmallM(field, t,
            PolynomialGF2mSmallM.RANDOM_IRREDUCIBLE_POLYNOMIAL, random);
        PolynomialRingGF2m ring = new PolynomialRingGF2m(field, gp);

        // matrix used to compute square roots in (GF(2^m))^t 
        PolynomialGF2mSmallM[] a = ring.getSquareRootMatrix();
        
        // generate canonical check matrix with a permutation
        PermutationCustom p = new PermutationCustom(n, random);
        HCheck h = GoppaCode.createNTS_KEMCheckMatrix(field, gp, p);
        GF2Matrix shortH = GF2MatrixUtils.getLeftSubMatrix(h.getHCheck(), n-m*t);//.getLeftSubMatrix(); //.getRightSubMatrix();

        // compute short systematic form of generator matrix
        GF2Matrix shortG = (GF2Matrix)shortH.computeTranspose();

        // extend to full systematic form
        GF2Matrix gPrime = shortG.extendLeftCompactForm();

        // obtain number of rows of G (= dimension of the code)
        int k = shortG.getNumRows();
        
        // random array of 256 bits param needed to encrypt in the future
        Random rand = new Random();
        int[] z = new int[l];
        for (int i = 0; i < l; i++) {
            z[i] = rand.nextBoolean() ? 0 : 1;
        }
        
        // generate keys
        NTS_KEM_PublicKeyParameters pubKey = 
                //new NTS_KEM_PublicKeyParameters(gPrime, t, l, n);
                new NTS_KEM_PublicKeyParameters(shortG, t, l, n);
        NTS_KEM_PrivateKeyParameters privKey = 
                new NTS_KEM_PrivateKeyParameters(
                        h.getA(), 
                        h.getH(), 
                        p, 
                        z,
                        k, 
                        n, 
                        field,
                        gp, 
                        l,
                        ring, 
                        h.getHCheck(), 
                        a
                );

        // return key pair
        return new AsymmetricCipherKeyPair(pubKey, privKey);
    }

    /**
     *
     * @param param
     */
    public void init(KeyGenerationParameters param)
    {
        this.initialize(param);
    }

    /**
     *
     * @return
     */
    public AsymmetricCipherKeyPair generateKeyPair()
    {
        return genKeyPair();
    }

}
