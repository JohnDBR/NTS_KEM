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
    
    public static String substractBinaryStrings(String a, String b) {
        /*String result = "", borrow = "0";
        if (a.length() > b.length()) {
            b = addCustomPadding(b, a.length());
        } else if (a.length() < b.length()) {
            a = addCustomPadding(a, b.length());
        }
        for (int i = 0; i < b.length(); i++) {
            result = result.concat(b.substring(i, i+1).equalsIgnoreCase("1") ? "0" : "1");
        }
        b = result;
        result = "";
        int k = b.length();
        do {            
            if (b.substring(k - 1, k).equalsIgnoreCase("0")) {
                b = b.substring(0, k - 1).concat("1").concat(b.substring(k, b.length()));
                k = 0;
            } else if (b.substring(k - 1, k).equalsIgnoreCase("1")) {
                b = b.substring(0, k - 1).concat("0").concat(b.substring(k, b.length()));
                k--;
            }
        } while (k > 0);*/
      
        /*int s = 0;          
        int i = a.length() - 1, j = b.length() - 1; 
        while (i >= 0 || j >= 0 || s == 1) 
        {
            s += ((i >= 0)? a.charAt(i) - '0': 0); 
            s += ((j >= 0)? b.charAt(j) - '0': 0); 
            result = (char)(s % 2 + '0') + result; 
            s /= 2; 
            i--; j--; 
        }*/        
        return addBinaryStrings(a, findTwoscomplementBinaryString(b));
    }
    
    static String addBinaryStrings(String a, String b) {
        String result = "";
        int s = 0;          
        int i = a.length() - 1, j = b.length() - 1; 
        while (i >= 0 || j >= 0 || s == 1) { 
            s += ((i >= 0)? a.charAt(i) - '0': 0); 
            s += ((j >= 0)? b.charAt(j) - '0': 0); 
            result = (char)(s % 2 + '0') + result; 
            s /= 2;
            i--; j--; 
        }  
        return result; 
    } 
    
    static String findTwoscomplementBinaryString(String a) { 
        StringBuffer str = new StringBuffer(a);
        int n = str.length();
        int i; 
        for (i = n-1 ; i >= 0 ; i--) {
            if (str.charAt(i) == '1') {
                break; 
            }
        }
        if (i == -1) {
            return "1" + str; 
        }
        for (int k = i-1 ; k >= 0; k--) 
        { 
            if (str.charAt(k) == '1') {
                str.replace(k, k+1, "0"); 
            } else {
                str.replace(k, k+1, "1"); 
            }
        } 
        return str.toString(); 
    } 
}
