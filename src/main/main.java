/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package main;

import java.nio.charset.Charset;
import nts_kem.NTS_KEM_Cipher;
import nts_kem.NTS_KEM_EncodeParameters;
import nts_kem.NTS_KEM_KeyGenerationParameters;
import nts_kem.NTS_KEM_KeyPairGenerator;
import nts_kem.NTS_KEM_Parameters;
import nts_kem.NTS_KEM_PrivateKeyParameters;
import nts_kem.NTS_KEM_PublicKeyParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.InvalidCipherTextException;
import pqc.math.linearalgebra.ByteUtils;


/**
 *
 * @author John Barbosa, Maximiliam Garcia, Andres Concha y Cristian de Marchena
 */
public class main {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // TODO code application logic here
        
        //Using the default values 
        //m = 11 the extension degree of the finite field GF(2^m) 
        //t = 50 the error correction capability of the code 
        //l = 256 the length of the random key to be encapsulated
        NTS_KEM_Parameters nkParams = new NTS_KEM_Parameters();
        //new McElieceParameters(int m, int t, int poly) to use custom values
        //PolynomialRingGF2.getIrreduciblePolynomial(m); to get a poly 
        
        //The key parameters share the same values of the crypo system
        NTS_KEM_KeyGenerationParameters mcKeyParams = 
                new NTS_KEM_KeyGenerationParameters(
                        CryptoServicesRegistrar.getSecureRandom(), 
                        nkParams
                );
        
        // Generating the public and private key of the crypto system
        NTS_KEM_KeyPairGenerator 
                nkKeyPairGenerator = new NTS_KEM_KeyPairGenerator();
        nkKeyPairGenerator.init(mcKeyParams);
        AsymmetricCipherKeyPair 
                generateKeyPair = nkKeyPairGenerator.generateKeyPair();
        
        NTS_KEM_PublicKeyParameters nkPublicKey 
                = (NTS_KEM_PublicKeyParameters) generateKeyPair.getPublic();
        
        NTS_KEM_PrivateKeyParameters nkPrivateKey 
                = (NTS_KEM_PrivateKeyParameters) generateKeyPair.getPrivate();
        
        // Uncomment to see the keys, it will take a lot of time printing
        
        //System.out.println("PubKey:");
        //System.out.println(nkPublicKey.getKey());
        
        //System.out.println("PrivKey:");
        //System.out.println(nkPrivateKey.getKey());
        
        NTS_KEM_Cipher nkChiper = new NTS_KEM_Cipher();
        nkChiper.init(true, nkPublicKey);

        NTS_KEM_EncodeParameters encodeParameters = nkChiper.encode();
        
        //System.out.println("kr = ");
        //System.out.println(ByteUtils.getBinaryStringFromBytes(
        //            encodeParameters.getKr().getEncoded()
        //        )
        //    );
        System.out.println("cbc = ");
        System.out.println(ByteUtils.getBinaryStringFromBytes(
                encodeParameters.getC().getEncoded()
        )
        );

        int[] i = new int[5];
        for (int j = 0; j < 5; j++) {
            i[j] = j;
        }
        int[] k = new int[5];
        for (int j = 0; j < 5; j++) {
            k[j] = j;
        }
        int[] result = new int[5];
        for (int j = 0; j < 5; j++) {
            result[j] = i[j]^k[j];
        }
    }
    
}
