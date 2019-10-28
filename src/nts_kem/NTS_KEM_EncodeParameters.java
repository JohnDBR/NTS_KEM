/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package nts_kem;

import org.bouncycastle.pqc.math.linearalgebra.GF2Vector;

/**
 *
 * @author john
 */
public class NTS_KEM_EncodeParameters {
    
    // Full error vector e ∈ Fn2 with Hamming weight T
    private GF2Vector e;
    
    // Ke vector that according to the paper is ke = Hl(e) ∈ Fl2
    private GF2Vector ke; 
    
    // Message vector that according to the paper is m = (ea | ke) ∈ Fk2
    private GF2Vector m;
    
    // c* that according to the paper is c* = (cb | cc) ∈ F(n-k+l)2
    private GF2Vector c;

    // Kr that according to the paper is kr = Hl(ke | e) ∈ Fl2
    private GF2Vector kr;

    /**
     * Constructor.
     * 
     * @param e         Full error vector e ∈ Fn2 with Hamming weight T
     * @param ke        Ke vector that according to the paper is 
     *                  ke = Hl(e) ∈ Fl2
     * @param m         Message vector that according to the paper is 
     *                  m = (ea | ke) ∈ Fk2
     * @param c         c* that according to the paper is 
     *                  c* = (cb | cc) ∈ F(n-k+l)2 
     * @param kr        Kr that according to the paper is kr = Hl(ke | e) ∈ Fl2
     */
    public NTS_KEM_EncodeParameters(GF2Vector e, GF2Vector ke, GF2Vector m, 
                                    GF2Vector c, GF2Vector kr) 
    {
        this.e = e;
        this.ke = ke;
        this.m = m;
        this.c = c;
        this.kr = kr;
    }

    public GF2Vector getE() {
        return e;
    }

    public GF2Vector getKe() {
        return ke;
    }

    public GF2Vector getM() {
        return m;
    }

    public GF2Vector getC() {
        return c;
    }

    public GF2Vector getKr() {
        return kr;
    }
    
    
}
