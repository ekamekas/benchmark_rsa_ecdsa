package Model.RSA;

import lombok.Data;

import java.math.BigInteger;

@Data
public class PrivateKeyModel {

    private BigInteger exponentD;       // Public exponent number for Decryption
    private BigInteger modulusN;          // RSA modulus n

    public PrivateKeyModel(BigInteger exponentD, BigInteger modulusN){
        this.exponentD = exponentD;
        this.modulusN = modulusN;
    }

}
