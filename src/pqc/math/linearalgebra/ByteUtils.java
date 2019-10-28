/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pqc.math.linearalgebra;

import java.nio.ByteBuffer;

/**
 *
 * @author john
 */
public class ByteUtils {
    
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
    
    public static byte[] getBytesFromBinaryString(String binaryString) {
        //return new BigInteger(bitString, 2).toByteArray();
        String fixedSize = addPadding(binaryString);
        byte[] bytes = new byte[fixedSize.length() / 8];
        int pos = 0;
        for (int i = 0; i < fixedSize.length(); i = i + 8) {
            short a = Short.parseShort(fixedSize.substring(i, i + 8), 2);
            ByteBuffer bytesb = ByteBuffer.allocate(2).putShort(a);
            byte[] array = bytesb.array();
            bytes[pos] = array[1];
            pos++;
        }
        return bytes;
    }

    public static int[] getBitsFromBytes(byte[] bytes) {
        String binaryString = getBinaryStringFromBytes(bytes);
        int[] bitsRepresentation = new int[binaryString.length()];
        for (int i = 0; i < binaryString.length(); i++) {
            bitsRepresentation[i] 
                    = binaryString.substring(i, i+1).equals("1") ? 1 : 0;
        }
        return bitsRepresentation;
    }
    
    public static String erasePadding(int expectedLength, String binaryString) {
        int leftBits = binaryString.length() - expectedLength;
        return binaryString.substring(leftBits, binaryString.length());
    }
    
    public static String addPadding(String binaryString) {
        String result = binaryString;
        int length = binaryString.length();
        if (length % 8 > 0) {
            length = length + (8 - length % 8);
        }
        while(result.length() < length) {
            result = "0".concat(result);
        }
        return result;
    }
    
    public static String addCustomPadding(String binaryString, int length) {
        String result = binaryString;
        while(result.length() < length) {
            result = "0".concat(result);
        }
        return result;
    }
}
