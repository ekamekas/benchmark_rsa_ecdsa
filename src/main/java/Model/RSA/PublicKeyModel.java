package Model.RSA;

import lombok.Data;

import java.math.BigInteger;

@Data
public class PublicKeyModel {

    private BigInteger coprimeE;        // Public exponent number for Encryption
    private BigInteger modulusN;          // RSA modulus n

    public PublicKeyModel(BigInteger coprimeE, BigInteger modulusN){
        this.coprimeE = coprimeE;
        this.modulusN = modulusN;
    }

}
