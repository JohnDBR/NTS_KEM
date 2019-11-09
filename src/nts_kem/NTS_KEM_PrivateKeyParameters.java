package nts_kem;

import org.bouncycastle.pqc.math.linearalgebra.GF2mField;
import org.bouncycastle.pqc.math.linearalgebra.PolynomialGF2mSmallM;
import pqc.math.linearalgebra.PermutationCustom;

/**
 *
 * @author maxim
 */
public class NTS_KEM_PrivateKeyParameters
    extends NTS_KEM_KeyParameters
{

    // the OID of the algorithm
    private String oid;
    
    // the length of the code
    private int n;
    
    // the dimension of the code, where <tt>k &gt;= n - mt</tt>
    private int k;

    // the permutation used to generate the check matrix
    private PermutationCustom p;
    
    // Array a to generate H matrix as the NTS_KEM paper specifies 
    private int[] a;

    // Array h to generate H matrix as the NTS_KEM paper specifies
    private int[] h;
    
    // Array z of 256 bits used for the decryption process
    private int[] z;
    
    // the underlying finite field
    private GF2mField field;

    // the irreducible Goppa polynomial
    private PolynomialGF2mSmallM goppaPoly;
    
    // length of the key to be encapsulated
    private int l;

    /**
     * Constructor.
     * 
     * @param n         the length of the code
     * @param k         the dimension of the code
     * @param a         Array a to generate H matrix as the NTS_KEM paper 
     *                  specifies 
     * @param h         Array h to generate H matrix as the NTS_KEM paper 
     *                  specifies 
     * @param p         the permutation used to generate the check matrix
     * @param z         Array z of 256 bits used for the decryption process
     * @param field     the field polynomial defining the finite field
     *                  <tt>GF(2<sup>m</sup>)</tt>
     * @param gp        the irreducible Goppa polynomial
     */
    public NTS_KEM_PrivateKeyParameters(int[] a, int[] h, PermutationCustom p,
                                        int[] z, int k, int n, GF2mField field,
                                        PolynomialGF2mSmallM gp, int l)
    {
        super(true, null);
        this.a = a;
        this.h = h;
        this.p = p;
        this.z = z;
        this.k = k;
        this.n = n;
        this.field = field;
        this.goppaPoly = gp;
        this.l = l;
    }
    
    /**
     * @return the length of the code
     */
    public int getN()
    {
        return n;
    }
    
    /**
     * @return the dimension of the code
     */
    public int getK()
    {
        return k;
    }
    
    /**
     * @return the finite field <tt>GF(2<sup>m</sup>)</tt>
     */
    public GF2mField getField()
    {
        return field;
    }
    
    /**
     * @return the irreducible Goppa polynomial
     */
    public PolynomialGF2mSmallM getGoppaPoly()
    {
        return goppaPoly;
    }

    /**
     * @return  Array a to generate H matrix as the NTS_KEM paper specifies
     */
    public int[] getA()
    {
        return a;
    }

    /**
     * @return Array h to generate H matrix as the NTS_KEM paper specifies 
     */
    public int[] getH()
    {
        return h;
    }

    /**
     * @return the permutation used to generate the check matrix
     */
    public PermutationCustom getP()
    {
        return p;
    }

    /**
     * @return Array z of 256 bits used for the decryption process
     */
    public int[] getZ()
    {
        return z;
    }    

    /**
     * @return the private key with string form
     */
    public String getKey() {
        return "(" + a.toString() + ", " + h.toString() + ", " +  
                p.getVector().toString() + ", " + z.toString() +")";
    }
    
    /**
     * @return length of the key to be encapsulated
     */
    public int getL() {
        return l;
    }

}
