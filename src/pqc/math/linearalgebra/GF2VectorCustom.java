/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pqc.math.linearalgebra;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.pqc.math.linearalgebra.GF2Vector;

/**
 *
 * @author john
 */
public class GF2VectorCustom extends GF2Vector {
    
    // Bytes array representation of the vector
    private byte[] byteArray;
    
    // Binary string representation of the vector 
    private String binaryString;

    /**
     * Constructor.
     * 
     * @param vector    GF2Vector representation of the vector
     */
    public GF2VectorCustom(GF2Vector vector) {
        super(vector);
        binaryString = ByteUtils.getBinaryStringFromBytes(vector.getEncoded());
        byteArray = ByteUtils.getBytesFromBinaryString(binaryString);
    }
    
    /**
     * Constructor.
     * 
     * @param binaryString  Binary string representation of the vector
     */
    public GF2VectorCustom(String binaryString) {
        super(GF2Vector.OS2VP(
                binaryString.length(), 
                ByteUtils.getBytesFromBinaryString(binaryString)
            )
        );
        this.binaryString = binaryString;
        this.byteArray = ByteUtils.getBytesFromBinaryString(binaryString);
        
    }
    
    /**
     * Constructor.
     * 
     * @param byteArray Byte array representation of the vector
     */
    public GF2VectorCustom(byte[] byteArray) {
        super(GF2Vector.OS2VP(
                byteArray.length, 
                byteArray
            )
        );
        this.binaryString = ByteUtils.getBinaryStringFromBytes(byteArray);
        this.byteArray = byteArray; 
    }
    
    /**
     * Constructor.
     * 
     * @param byteArray         Byte array representation of the vector
     * @param expectedLength    Int of the expected length in number of bits
     */
    public GF2VectorCustom(byte[] byteArray, int expectedLength) {
        super(GF2Vector.OS2VP(
                expectedLength, 
                byteArray
            )
        );
        this.binaryString = ByteUtils.getBinaryStringFromBytes(byteArray);
        if (binaryString.length() > expectedLength) {
            binaryString = ByteUtils.erasePadding(expectedLength, binaryString);
        }
        this.byteArray = byteArray; 
    }
        
    /**
     * Constructor.
     * 
     * @param vector        GF2Vector representation of the vector
     * @param binaryString  Binary string representation of the vector 
     * @param byteArray     Byte array representation of the vector
     */
    public GF2VectorCustom(GF2Vector vector, String binaryString, 
                           byte[] byteArray) 
    {
        super(vector);
        this.binaryString = binaryString;
        this.byteArray = byteArray;
    }

    public byte[] getByteArray() {
        return byteArray;
    }

    public String getBinaryString() {
        return binaryString;
    }
    
    public GF2VectorCustom concatLeft(GF2Vector a, int expectedLength) {
        String aBinaryString = ByteUtils.getBinaryStringFromBytes(
                a.getEncoded()
            );
        String abBinaryString = aBinaryString.concat(binaryString);
        return new GF2VectorCustom(abBinaryString);
    }
    
    public GF2VectorCustom concatRight(GF2Vector a, int expectedLength)
    {
        String aBinaryString = ByteUtils.getBinaryStringFromBytes(
                a.getEncoded()
            );
        String baBinaryString = binaryString.concat(aBinaryString);
        return new GF2VectorCustom(baBinaryString);
    }
    
    public GF2VectorCustom concatLeft(GF2Vector a) {
        String aBinaryString = ByteUtils.getBinaryStringFromBytes(
                a.getEncoded()
            );
        String abBinaryString = aBinaryString.concat(binaryString);
        return new GF2VectorCustom(abBinaryString);
    }
    
    public GF2VectorCustom concatRight(GF2Vector a) {
        String aBinaryString = ByteUtils.getBinaryStringFromBytes(
                a.getEncoded()
            );
        String baBinaryString = binaryString.concat(aBinaryString);
        return new GF2VectorCustom(baBinaryString);
    }
    
    public GF2VectorCustom concatLeft(GF2VectorCustom a, int expectedLength) {
        return new GF2VectorCustom(a.getBinaryString().concat(binaryString));
    }
    
    public GF2VectorCustom concatRight(GF2VectorCustom a, int expectedLength)
    {                
        return new GF2VectorCustom(binaryString.concat(a.getBinaryString()));
    }
    
    public GF2VectorCustom concatLeft(GF2VectorCustom a) {
        return new GF2VectorCustom(a.getBinaryString().concat(binaryString));
    }
    
    public GF2VectorCustom concatRight(GF2VectorCustom a) {
        return new GF2VectorCustom(binaryString.concat(a.getBinaryString()));
    }
    
    public GF2VectorCustom SHA3(int bitLength) {
        SHAKEDigest sd = new SHAKEDigest(bitLength);
        sd.update(byteArray, 0, byteArray.length);
        byte[] newArray = new byte[bitLength / 8];
        sd.doFinal(newArray, 0);
        return new GF2VectorCustom(newArray, bitLength);
    }
    
}
