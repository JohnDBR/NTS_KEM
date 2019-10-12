package nts_kem;

import pqc.math.linearalgebra.PermutationCustom;


public class NTS_KEM_PrivateKeyParameters
    extends NTS_KEM_KeyParameters
{

    // the OID of the algorithm
    private String oid;

    // the permutation used to generate the check matrix
    private PermutationCustom p;
    
    // Array a to generate H matrix as the NTS_KEM paper specifies 
    int[] a;

    // Array h to generate H matrix as the NTS_KEM paper specifies
    int[] h;
    
    // Array z of 256 bits used for the decryption process
    int[] z;

    /**
     * Constructor.
     *
     * @param a         Array a to generate H matrix as the NTS_KEM paper 
     *                  specifies 
     * @param h         Array h to generate H matrix as the NTS_KEM paper 
     *                  specifies 
     * @param p         the permutation used to generate the check matrix
     * @param z         Array z of 256 bits used for the decryption process

     */
    public NTS_KEM_PrivateKeyParameters(int[] a, int[] h, PermutationCustom p,
                                        int[] z)
    {
        super(true, null);
        this.a = a;
        this.h = h;
        this.p = p;
        this.z = z;
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

}
