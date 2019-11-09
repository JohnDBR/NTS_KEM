package nts_kem;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Random;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.CSHAKEDigest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageEncryptor;
import org.bouncycastle.pqc.crypto.mceliece.McEliecePublicKeyParameters;
import org.bouncycastle.pqc.math.linearalgebra.GF2Matrix;
import org.bouncycastle.pqc.math.linearalgebra.GF2Vector;
import org.bouncycastle.pqc.math.linearalgebra.GF2mField;
import org.bouncycastle.pqc.math.linearalgebra.GoppaCode;
import org.bouncycastle.pqc.math.linearalgebra.Permutation;
import org.bouncycastle.pqc.math.linearalgebra.PolynomialGF2mSmallM;
import org.bouncycastle.pqc.math.linearalgebra.Vector;
import pqc.math.linearalgebra.ByteUtils;
import pqc.math.linearalgebra.GF2VectorCustom;
import pqc.math.linearalgebra.GF2VectorUtils;

/**
 * This class implements the NTS KEM Public Key cryptosystem.
 */
public class NTS_KEM_Cipher
        implements KeyEncapsulator {

    /**
     * The OID of the algorithm.
     */
    public static final String OID = "1.3.6.1.4.1.8301.3.1.3.4.1";

    // the source of randomness
    private SecureRandom sr;

    // the McEliece main parameters
    private int n, k, t;

    // The maximum number of bytes the cipher can decrypt
    public int maxPlainTextSize;

    // The maximum number of bytes the cipher can encrypt
    public int cipherTextSize;

    private NTS_KEM_KeyParameters key;
    private boolean forEncryption;

    public void init(boolean forEncryption,
            CipherParameters param) {
        this.forEncryption = forEncryption;
        if (forEncryption) {
            if (param instanceof ParametersWithRandom) {
                ParametersWithRandom rParam = (ParametersWithRandom) param;

                this.sr = rParam.getRandom();
                this.key = (NTS_KEM_PublicKeyParameters) rParam.getParameters();
                this.initCipherEncrypt((NTS_KEM_PublicKeyParameters) key);

            } else {
                this.sr = CryptoServicesRegistrar.getSecureRandom();
                this.key = (NTS_KEM_PublicKeyParameters) param;
                this.initCipherEncrypt((NTS_KEM_PublicKeyParameters) key);
            }
        } else {
            this.key = (NTS_KEM_PrivateKeyParameters) param;
            this.initCipherDecrypt((NTS_KEM_PrivateKeyParameters) key);
        }

    }

    /**
     * Return the key size of the given key object.
     *
     * @param key the McElieceKeyParameters object
     * @return the keysize of the given key object
     */
    public int getKeySize(NTS_KEM_KeyParameters key) {

        if (key instanceof NTS_KEM_PublicKeyParameters) {
            return ((NTS_KEM_PublicKeyParameters) key).getN();

        }
        if (key instanceof NTS_KEM_PrivateKeyParameters) {
            return ((NTS_KEM_PrivateKeyParameters) key).getN();
        }
        throw new IllegalArgumentException("unsupported type");

    }

    private void initCipherEncrypt(NTS_KEM_PublicKeyParameters pubKey) {
        this.sr = sr != null ? sr : CryptoServicesRegistrar.getSecureRandom();
        n = pubKey.getN();
        k = pubKey.getK();
        t = pubKey.getT();
        cipherTextSize = n >> 3;
        maxPlainTextSize = (k >> 3);
    }

    private void initCipherDecrypt(NTS_KEM_PrivateKeyParameters privKey) {
        n = privKey.getN();
        k = privKey.getK();

        maxPlainTextSize = (k >> 3);
        cipherTextSize = n >> 3;
    }
    
    /**
     * Generate uniformly at random an error vector e ∈ Fn2 with Hamming 
     * weight τ.
     *
     * @return input the random vector
     */
    private byte[] RandomVectorE() {
        // Initializing the vector with 0
        byte[] e = new byte[n];
        for (int j = 0; j < n; j++) {
            e[j] = 0;
        }
        
        //Generating all the random positions and filling them with 1
        ArrayList<Integer> randomPositions = new ArrayList<>();
        Random rand = new Random();
        for (int i = 0; i < t; i++) {
            int randomPosition;
            do {                
                randomPosition = rand.nextInt(n);
            } while (randomPositions.contains(randomPosition));
            randomPositions.add(randomPosition);
            e[randomPosition] = 1;
        }
        
        return e;
    }

    /**
     * Encoding
     *
     * @return a NTS_KEM_EncodeParameters instance
     */
    public NTS_KEM_EncodeParameters encode() {
        if (!forEncryption) {
            throw new IllegalStateException("cipher initialised for decryption");
        }
        // Generate uniformly at random an error vector e ∈ Fn2 with Hamming 
        // * weight τ.
        GF2VectorCustom e = new GF2VectorCustom(new GF2Vector(n, t, sr));
        byte[] eArray = e.getByteArray();
        
        int kMinusL = k - ((NTS_KEM_PublicKeyParameters) key).getL();
        int eaArrayLength = kMinusL / 8 + 1;
        byte[] eaArray = new byte[eaArrayLength];
        for (int i = 0; i < eaArray.length; i++) {
            eaArray[i] = eArray[i];
        }
        GF2VectorCustom ea = new GF2VectorCustom(eaArray, kMinusL);
        
        // Compute ke = Hl(e) ∈ Fl2 .
        GF2VectorCustom ke = new GF2VectorCustom(GF2VectorUtils.SHA3(
                eaArray, 
                ((NTS_KEM_PublicKeyParameters) key).getL()
            )
        );
                
        String eaBitRepresentation = ea.getBinaryString();
        eaBitRepresentation = ByteUtils.erasePadding(
                kMinusL, 
                eaBitRepresentation
            );
        String keBitRepresentation = ke.getBinaryString();
        // Construct the message vector m = (ea | ke ) ∈ Fk2 .
        GF2VectorCustom m = ke.concatLeft(new GF2VectorCustom(eaBitRepresentation), k);
        
        // Compute cb = ke + eb
        int kPlusL = k + ((NTS_KEM_PublicKeyParameters) key).getL();
        GF2VectorCustom eb = new GF2VectorCustom(e.getBinaryString().substring(k, kPlusL));
        GF2VectorCustom cb = new GF2VectorCustom((GF2Vector) ke.add(eb));
        
        // Compute cc = (m · Q) + ec
        GF2Matrix g = ((NTS_KEM_PublicKeyParameters) key).getG();
        Vector mG = g.leftMultiply(m);
        GF2Vector ec = new GF2VectorCustom(e.getBinaryString().substring(k, n));
        GF2VectorCustom mGEc = new GF2VectorCustom((GF2Vector) mG.add(ec));
        
        // Compute c* = (cb | cc)
        String ccBitRepresentation = mGEc.getBinaryString(); 
        ccBitRepresentation = ByteUtils.erasePadding(n-k, ccBitRepresentation);
        GF2VectorCustom cc = new GF2VectorCustom(ccBitRepresentation);
        GF2VectorCustom cbc = cb.concatRight(cc);
        
        // Compute kr = Hl(ke | e)
        GF2VectorCustom kee = ke.concatRight(e);
        GF2Vector kr = kee.SHA3(((NTS_KEM_PublicKeyParameters) key).getL());
        
        return new NTS_KEM_EncodeParameters(cbc);
    }
    
    public GF2VectorCustom decode(NTS_KEM_EncodeParameters ep) {
        return null;
    }
}
