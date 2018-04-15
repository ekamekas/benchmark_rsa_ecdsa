package Application;

import Service.RSAService;

import java.math.BigInteger;
import java.security.SecureRandom;

public class Application {

    public static void main(String[] args){
//      Initiating Objects and Variables
        int KEY_LENGTH = 4096;
        RSAService rsaService = new RSAService(KEY_LENGTH);
        BigInteger message = new BigInteger("21483");
        System.out.println(String.format("-- KeyPair --\n%s", rsaService.generateKeyPair().toString()));
        BigInteger encrypted = rsaService.encrypt(message, rsaService.getRsaModel());
        BigInteger decrypted = rsaService.decrypt(encrypted, rsaService.getRsaModel());
        System.out.println(String.format("-- RSA Params --\n%s", rsaService.toString()));
        System.out.println(String.format("Message : %s", message.toString()));
        System.out.println(String.format("Encrypted : %s", encrypted.toString()));
        System.out.println(String.format("Decrypted : %s", decrypted.toString()));

    }

}
