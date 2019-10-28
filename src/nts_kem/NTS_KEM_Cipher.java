package nts_kem;

import java.math.BigInteger;
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

/**
 * This class implements the NTS KEM Public Key cryptosystem.
 */
public class NTS_KEM_Cipher {
        //implements MessageEncryptor {

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
     * @return the cipher text
     */
    public byte[] Encode() {
        if (!forEncryption) {
            throw new IllegalStateException("cipher initialised for decryption");
        }
        // Generate uniformly at random an error vector e ∈ Fn2 with Hamming 
        // * weight τ.
        byte[] e = RandomVectorE();
        //GF2Vector e = new GF2Vector(input.length, input);
        //int[] vec = e.getVecArray();
        //GF2Vector ea = e.extractLeftVector(k-key.getParameters().getL());
        //GF2Vector m = computeInputRepresentative(input);
        //GF2Vector z = new GF2Vector(n, t, sr);
        int kMinusL = k - ((NTS_KEM_PublicKeyParameters) key).getL();
        byte[] ea = new byte[kMinusL];
        for (int i = 0; i < ea.length; i++) {
            ea[i] = e[i];
        }
        
        // Compute ke = Hl(e) ∈ Fl2 .
        SHAKEDigest sd = new SHAKEDigest(((NTS_KEM_PublicKeyParameters) key).getL());
        sd.update(ea, 0, ea.length);
        byte[] ke = new byte[((NTS_KEM_PublicKeyParameters) key).getL()];//ea.length / 8];
        sd.doFinal(ke, 0);
        System.out.println(new String(ke, Charset.forName("UTF-8")));

        
        // Construct the message vector m = (ea|ke) ∈ Fk2
        int[] m = new int[k];
        for (int i = 0; i < kMinusL; i++) {
            m[i] = ea[i];
        }
        for (int i = kMinusL; i < kMinusL + ((NTS_KEM_PublicKeyParameters) key).getL(); i++) {
            m[i] = ke[i - kMinusL];
        }

        //GF2Vector m = new GF2Vector(int[] v, int length);
        
        //GF2Matrix g = ((NTS_KEM_PublicKeyParameters) key).getG();
        //Vector mG = g.leftMultiply(m);
        //GF2Vector mGZ = (GF2Vector) mG.add(z);

        return ke;//mGZ.getEncoded();
    }

    private GF2Vector computeInputRepresentative(byte[] input) {
        byte[] data = new byte[maxPlainTextSize + ((k & 0x07) != 0 ? 1 : 0)];
        System.arraycopy(input, 0, data, 0, input.length);
        data[input.length] = 0x01;
        return GF2Vector.OS2VP(k, data);
    }
    
    // Some handy methods to deal with all the code

    public static String getBinaryStringFromBytes(byte[] bytes) {
        String s1 = "";
        for (byte i : bytes) {
            s1 = s1.concat(
                String.format(
                    "%8s",
                    Integer.toBinaryString(i & 0xFF)
                ).replace(' ', '0')
            );
        }
        return s1;
    }
    
    public static byte[] getBytesFromBinaryString(String bitString) {
        return new BigInteger(bitString, 2).toByteArray();
    }

}
