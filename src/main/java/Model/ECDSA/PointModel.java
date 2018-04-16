package Model.ECDSA;

import lombok.Data;

import java.math.BigInteger;

@Data
public class PointModel {

    private BigInteger x;
    private BigInteger y;

    public PointModel(BigInteger x, BigInteger y){
        this.x = x;
        this.y = y;
    }

}
