package Model.RSA;

import lombok.Data;

import java.util.Base64;

@Data
public class RSAModel{

    private PublicKeyModel publicKey;
    private PrivateKeyModel privateKey;

    @Override
    public String toString(){
        return String.format("Public Key : %s\nPrivate Key : %s\nModulus Length : %s",
                Base64.getEncoder().encodeToString(publicKey.getCoprimeE().toByteArray()),
                Base64.getEncoder().encodeToString(privateKey.getExponentD().toByteArray()),
                publicKey.getModulusN().toString());
    }

}
