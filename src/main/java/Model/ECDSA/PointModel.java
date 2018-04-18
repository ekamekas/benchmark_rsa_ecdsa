package Model.ECDSA;

import lombok.Data;

import java.math.BigInteger;

/*
    Mas Eka Setiawan - <mas.eka@ui.ac.id>
    Computer Engineering, University of Indonesia
    Benchmarking RSA and ECDSA Algorithm
*/

@Data
public class PointModel {

    private BigInteger x;
    private BigInteger y;

    public PointModel(BigInteger x, BigInteger y){
        this.x = x;
        this.y = y;
    }

}
