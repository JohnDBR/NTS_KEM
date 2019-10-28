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
        //byte[] e = RandomVectorE();
        //GF2Vector e = new GF2Vector(input.length, input);
        GF2Vector e = new GF2Vector(n, t, sr);
        byte[] eArray = e.getEncoded();
        //int[] vec = e.getVecArray();
        //GF2Vector ea = e.extractLeftVector(((NTS_KEM_PublicKeyParameters) key).getL());
        //byte[] eaArray = ea.getEncoded();
        //GF2Vector m = computeInputRepresentative(input);
        //GF2Vector z = new GF2Vector(n, t, sr);
        
        int kMinusL = k - ((NTS_KEM_PublicKeyParameters) key).getL();
        int eaArrayLength = kMinusL / 8 + 1;
        byte[] eaArray = new byte[eaArrayLength];
        for (int i = 0; i < eaArray.length; i++) {
            eaArray[i] = eArray[i];
        }
        GF2Vector ea = GF2Vector.OS2VP(kMinusL, eaArray);
        
        // Compute ke = Hl(e) ∈ Fl2 .
        SHAKEDigest sd = new SHAKEDigest(
                ((NTS_KEM_PublicKeyParameters) key).getL()
            );
        sd.update(eaArray, 0, eaArray.length);
        byte[] keArray = new byte[
                ((NTS_KEM_PublicKeyParameters) key).getL() / 8
            ];//ea.length / 8];
        sd.doFinal(keArray, 0);
        GF2Vector ke = GF2Vector.OS2VP(
                ((NTS_KEM_PublicKeyParameters) key).getL(), 
                keArray
            );

        
        // Construct the message vector m = (ea | ke) ∈ Fk2
        //int[] m = new int[k];
        //for (int i = 0; i < kMinusL; i++) {
        //    m[i] = ea[i];
        //}
        //for (int i = kMinusL; i < kMinusL + ((NTS_KEM_PublicKeyParameters) key).getL(); i++) {
        //    m[i] = ke[i - kMinusL];
        //}
        String eBitRepresentation = ByteUtils.getBinaryStringFromBytes(
                e.getEncoded()
            );
        String eaBitRepresentation = ByteUtils.getBinaryStringFromBytes(
                eaArray
            );
        eaBitRepresentation = ByteUtils.erasePadding(
                kMinusL, 
                eaBitRepresentation
            );
        String keBitRepresentation = ByteUtils.getBinaryStringFromBytes(
                keArray
            );
        String mBitRepresentation = eaBitRepresentation.concat(
                keBitRepresentation
            );
        byte[] mArray = ByteUtils.getBytesFromBinaryString(mBitRepresentation);
        GF2Vector m = GF2Vector.OS2VP(k, mArray);
        //GF2Vector m = new GF2Vector(int[] v, int length);
        
        // Compute cb = ke + eb
        int kPlusL = k + ((NTS_KEM_PublicKeyParameters) key).getL();
        String ebBitRepresentation = eBitRepresentation.substring(k, kPlusL);
        byte[] ebArray = ByteUtils.getBytesFromBinaryString(
                ebBitRepresentation
            );
        GF2Vector eb = GF2Vector.OS2VP(
                ((NTS_KEM_PublicKeyParameters) key).getL(), 
                ebArray
            );
        GF2Vector cb = (GF2Vector) ke.add(eb);
        
        // Compute cc = (m · Q) + ec
        GF2Matrix g = ((NTS_KEM_PublicKeyParameters) key).getG();
        Vector mG = g.leftMultiply(m);
        String ecBitRepresentation = eBitRepresentation.substring(k, n);
        //String ecForXorBitRep = addCustomPadding(ecBitRepresentation, n);
        //byte[] ecArray = getBytesFromBinaryString(ecForXorBitRep);
        //GF2Vector ec = GF2Vector.OS2VP(n, ecArray);
        byte[] ecArray = ByteUtils.getBytesFromBinaryString(
                ecBitRepresentation
            );
        GF2Vector ec = GF2Vector.OS2VP(n-k, ecArray);
        byte[] mgArray = mG.getEncoded();
        //GF2Vector mGEc = (GF2Vector) mG.add(ec);
        String mgBitRepresentation = ByteUtils.getBinaryStringFromBytes(
                mgArray
            );
        String mgForXorBitRep = ByteUtils.erasePadding(
                n-k, 
                mgBitRepresentation
            );
        byte[] mgForXorArray = ByteUtils.getBytesFromBinaryString(
                mgForXorBitRep
            );
        GF2Vector mGForXor = GF2Vector.OS2VP(n-k, mgForXorArray);
        GF2Vector mGEc = (GF2Vector) mGForXor.add(ec);
        
        // Compute c* = (cb | cc)
        String cbBitRepresentation = ByteUtils.getBinaryStringFromBytes(
                cb.getEncoded()
            );
        String ccBitRepresentation = ByteUtils.getBinaryStringFromBytes(
                mGEc.getEncoded()
            );
        ccBitRepresentation = ByteUtils.erasePadding(n-k, ccBitRepresentation);
        String cbcBitRepresentation = cbBitRepresentation.concat(
                ccBitRepresentation
            );
        byte[] cbcArray = ByteUtils.getBytesFromBinaryString(
                cbcBitRepresentation
            );
        int nMinuskPlusL = n - k + ((NTS_KEM_PublicKeyParameters) key).getL();
        GF2Vector cbc = GF2Vector.OS2VP(nMinuskPlusL, cbcArray);
        
        // Compute kr = Hl(ke | e)
        String keeBitRepresentation = keBitRepresentation.concat(
                eBitRepresentation
            );
        byte[] keeArray = ByteUtils.getBytesFromBinaryString(
                keeBitRepresentation
            );
        //GF2Vector kee = GF2Vector.OS2VP(k, keeArray);
        SHAKEDigest sd2 = new SHAKEDigest(
                ((NTS_KEM_PublicKeyParameters) key).getL()
            );
        sd2.update(keeArray, 0, keeArray.length);
        int nPlusL = n + ((NTS_KEM_PublicKeyParameters) key).getL();
        byte[] krArray = new byte[
                ((NTS_KEM_PublicKeyParameters) key).getL() / 8
            ];
        sd.doFinal(krArray, 0);
        GF2Vector kr = GF2Vector.OS2VP(
                ((NTS_KEM_PublicKeyParameters) key).getL(), 
                krArray
            );
        
        return new NTS_KEM_EncodeParameters(e, ke, m, cbc, kr);
    }

    private GF2Vector computeInputRepresentative(byte[] input) {
        byte[] data = new byte[maxPlainTextSize + ((k & 0x07) != 0 ? 1 : 0)];
        System.arraycopy(input, 0, data, 0, input.length);
        data[input.length] = 0x01;
        return GF2Vector.OS2VP(k, data);
    }
    
    public byte[] decode(NTS_KEM_EncodeParameters ep) {
        return null;
    }
}
