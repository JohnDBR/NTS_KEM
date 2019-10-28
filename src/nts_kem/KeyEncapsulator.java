/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package nts_kem;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 *
 * @author john
 */
public interface KeyEncapsulator {
    
    public void init(boolean arg0, CipherParameters arg1);

    public NTS_KEM_EncodeParameters encode();

    public byte[] decode(NTS_KEM_EncodeParameters ep) throws InvalidCipherTextException;
}