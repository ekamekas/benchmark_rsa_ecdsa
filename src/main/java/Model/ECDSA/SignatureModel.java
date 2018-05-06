package Model.ECDSA;

import lombok.Data;

import java.math.BigInteger;

@Data
public class SignatureModel {

    private BigInteger r;
    private BigInteger s;

    public SignatureModel(BigInteger r, BigInteger s){
        this.r = r;
        this.s = s;
    }

}
