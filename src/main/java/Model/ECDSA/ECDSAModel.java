package Model.ECDSA;

import lombok.Data;

@Data
public class ECDSAModel {

    private String publicKey;
    private String privateKey;
    private PointModel ecdsaPoint;

}
