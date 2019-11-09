/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pqc.math.linearalgebra;

import org.bouncycastle.pqc.math.linearalgebra.GF2Matrix;
import org.bouncycastle.pqc.math.linearalgebra.GF2Vector;
import org.bouncycastle.pqc.math.linearalgebra.LittleEndianConversions;

/**
 *
 * @author john
 */
public class GF2MatrixUtils {
    
    public static GF2Matrix getLeftSubMatrix(GF2Matrix matrix, int newColumnLength){
        
        int [][] intArray = matrix.getIntArray();
        int byteLen = (intArray[0].length * 32 + 7) >> 3;
        String[] stringArray = new String[intArray.length];
        
        int [][] resultMatrix = new int[intArray.length][];
        for (int i = 0; i < intArray.length; i++) {
            resultMatrix[i] = GF2Vector.OS2VP(
                    newColumnLength, 
                    ByteUtils.getBytesFromBinaryString(
                            ByteUtils.getBinaryStringFromBytes(
                                    LittleEndianConversions.toByteArray(
                                            intArray[i], 
                                            byteLen
                                    )
                            ).substring(0, newColumnLength)
                    )
            ).getVecArray();
        }
        
        return new GF2Matrix(newColumnLength, resultMatrix);
    }
    
}
