/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pqc.math.linearalgebra;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.pqc.math.linearalgebra.GF2Vector;

/**
 *
 * @author john
 */
public class GF2VectorUtils {
    
    private static GF2Vector concatLeftToRight(GF2Vector a, GF2Vector b,
                                               int expectedLength) 
    {
        String aBinaryString = ByteUtils.getBinaryStringFromBytes(
                a.getEncoded()
            );
        String bBinaryString = ByteUtils.getBinaryStringFromBytes(
                b.getEncoded()
            );
        String abBinaryString = aBinaryString.concat(bBinaryString);
        return GF2Vector.OS2VP(
                expectedLength, 
                ByteUtils.getBytesFromBinaryString(abBinaryString)
            );
    }
    
    private static GF2Vector concatRightToLeft(GF2Vector a, GF2Vector b,
                                               int expectedLength)
    {
        String aBinaryString = ByteUtils.getBinaryStringFromBytes(
                a.getEncoded()
            );
        String bBinaryString = ByteUtils.getBinaryStringFromBytes(
                b.getEncoded()
            );
        String baBinaryString = aBinaryString.concat(bBinaryString);
        return GF2Vector.OS2VP(
                expectedLength, 
                ByteUtils.getBytesFromBinaryString(baBinaryString)
            );
    }
    
    private static GF2Vector concatLeftToRight(GF2Vector a, GF2Vector b) {
        String aBinaryString = ByteUtils.getBinaryStringFromBytes(
                a.getEncoded()
            );
        String bBinaryString = ByteUtils.getBinaryStringFromBytes(
                b.getEncoded()
            );
        String abBinaryString = aBinaryString.concat(bBinaryString);
        return GF2Vector.OS2VP(
                abBinaryString.length(), 
                ByteUtils.getBytesFromBinaryString(abBinaryString)
            );
    }
    
    private static GF2Vector concatRightToLeft(GF2Vector a, GF2Vector b) {
        String aBinaryString = ByteUtils.getBinaryStringFromBytes(
                a.getEncoded()
            );
        String bBinaryString = ByteUtils.getBinaryStringFromBytes(
                b.getEncoded()
            );
        String baBinaryString = aBinaryString.concat(bBinaryString);
        return GF2Vector.OS2VP(
                baBinaryString.length(), 
                ByteUtils.getBytesFromBinaryString(baBinaryString)
            );
    }
    
    private static GF2Vector SHA3(GF2Vector vector, int bitLength) {
        byte[] byteArray = vector.getEncoded();
        SHAKEDigest sd = new SHAKEDigest(bitLength);
        sd.update(byteArray, 0, byteArray.length);
        byte[] newArray = new byte[bitLength / 8];
        sd.doFinal(newArray, 0);
        return GF2Vector.OS2VP(bitLength, newArray);
    }
    
    private static GF2Vector SHA3(String binaryString, int bitLength) {
        byte[] byteArray = ByteUtils.getBytesFromBinaryString(binaryString);
        SHAKEDigest sd = new SHAKEDigest(bitLength);
        sd.update(byteArray, 0, byteArray.length);
        byte[] newArray = new byte[bitLength / 8];
        sd.doFinal(newArray, 0);
        return GF2Vector.OS2VP(bitLength, newArray);
    }
    
    private static GF2Vector computeInputRepresentative(byte[] input, 
                                                        int maxPlainTextSize, 
                                                        int k) 
    {
        byte[] data = new byte[maxPlainTextSize + ((k & 0x07) != 0 ? 1 : 0)];
        System.arraycopy(input, 0, data, 0, input.length);
        data[input.length] = 0x01;
        return GF2Vector.OS2VP(k, data);
    }
    
    private static byte[] computeMessage(GF2Vector mr)
            throws InvalidCipherTextException {
        byte[] mrBytes = mr.getEncoded();
        // find first non-zero byte
        int index;
        for (index = mrBytes.length - 1; index >= 0 && mrBytes[index] == 0; index--) {
            ;
        }

        // check if padding byte is valid
        if (index < 0 || mrBytes[index] != 0x01) {
            throw new InvalidCipherTextException("Bad Padding: invalid ciphertext");
        }

        // extract and return message
        byte[] mBytes = new byte[index];
        System.arraycopy(mrBytes, 0, mBytes, 0, index);
        return mBytes;
    }
}
