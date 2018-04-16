package Model.ECDSA;

import lombok.Data;

import java.math.BigInteger;

@Data
public class ECDSAModel {

    // ECDSA domain parameters
    /*
        Prime modulus (p)
        Prime order (n)
        Coefficient (a)
        Coefficient (b)
        Cofactor (h)
        Base point (G)
     */
    private int keyLength;
    private BigInteger primeModulus;    // p
    private BigInteger primeOrder;      // n
    private BigInteger cofactor;        // h
    // For equation y^2 = x^3 + ax + b
    private BigInteger coefficientA;    // a
    private BigInteger coefficientB;    // b
    // End
    private PointModel baseGenerator;   // G
    private BigInteger seed;             // for generating E
    // End

    // ECDSA key pair
    private PointModel publicKey;       // Q(x,y)
    private BigInteger privateKey;      // d
    // End

}
