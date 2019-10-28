package nts_kem;

import org.bouncycastle.pqc.math.linearalgebra.GF2Matrix;

/**
 *
 * @author maxim
 */
public class NTS_KEM_PublicKeyParameters
        extends NTS_KEM_KeyParameters {

    // the length of the code
    private int n;
    
    // length of the key to be encapsulated
    private int l;

    // the error correction capability of the code
    private int t;

    // the generator matrix short form
    private GF2Matrix g;

    /**
     * Constructor.
     *
     * @param g the generator matrix
     * @param t the error correction capability of the code
     * @param l length of the key to be encapsulated
     * @param n the length of the code
     */
    public NTS_KEM_PublicKeyParameters(GF2Matrix g, int t, int l, int n) {
        super(false, null);
        this.g = new GF2Matrix(g);
        this.t = t;
        this.l = l;
        this.n = n;
    }
    
    /**
     * @return the length of the code
     */
    public int getN()
    {
        return n;
    }

    /**
     * @return length of the key to be encapsulated
     */
    public int getL() {
        return l;
    }

    /**
     * @return the error correction capability of the code
     */
    public int getT() {
        return t;
    }

    /**
     * @return the generator matrix
     */
    public GF2Matrix getG() {
        return g;
    }

    /**
     * @return the dimension of the code
     */
    public int getK() {
        return g.getNumRows();
    }

    /**
     * @return the public key with string form
     */
    public String getKey() {
        return "(" + g.toString() + "," + t + ", " + l + ")";
    }
}
