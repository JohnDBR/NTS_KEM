package nts_kem;

import org.bouncycastle.pqc.math.linearalgebra.GF2Matrix;

/**
 *
 * @author maxim
 */
public class NTS_KEM_PublicKeyParameters
        extends NTS_KEM_KeyParameters {

    // length of the key to be encapsulated
    private int l;

    // the error correction capability of the code
    private int t;

    // the generator matrix short form
    private GF2Matrix g;

    /**
     * Constructor.
     *
     * @param l length of the key to be encapsulated
     * @param t the error correction capability of the code
     * @param g the generator matrix
     */
    public NTS_KEM_PublicKeyParameters(GF2Matrix g, int t, int l) {
        super(false, null);
        this.l = l;
        this.t = t;
        this.g = new GF2Matrix(g);
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
