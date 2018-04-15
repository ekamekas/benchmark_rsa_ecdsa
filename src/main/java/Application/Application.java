package Application;

import Model.RSA.RSAModel;
import Service.RSAService;

import java.math.BigInteger;
import java.security.SecureRandom;

import Utils.Hash.HashUtil;

public class Application {

    public static void main(String[] args){
        HashUtil hashUtil = new HashUtil();
//      Initiating Objects and Variables
        int KEY_LENGTH = 1024;
        RSAService rsaService = new RSAService(KEY_LENGTH);
        BigInteger message = new BigInteger("21483");
        message = hashUtil.digest(message, HashUtil.AlgorithmID.SHA_256);
        System.out.println(String.format("Hashed :%s\n", message));
        RSAModel keyPair = rsaService.generateKeyPair();
        BigInteger encrypted = rsaService.encrypt(message, keyPair);
        BigInteger decrypted = rsaService.decrypt(encrypted, keyPair);

        System.out.println(String.format("-- KeyPair --\n%s", keyPair.toString()));
        System.out.println(String.format("-- RSA Params --\n%s", rsaService.toString()));
        System.out.println(String.format("Message : %s", message.toString()));
        System.out.println(String.format("Encrypted : %s", encrypted.toString()));
        System.out.println(String.format("Decrypted : %s", decrypted.toString()));

    }

}
