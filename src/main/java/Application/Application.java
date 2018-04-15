package Application;

import Model.RSA.RSAModel;
import Service.RSAService;

import java.math.BigInteger;
import java.security.SecureRandom;

import Utils.Hash.HashUtil;

/*
    TODO:
    > Create ECDSA Service, Model, Utils
    > Create looped test environment to take the data
    > Inject benchmarking code/framework to measure resource allocation (CPU/Memory)
    > Export the data into file or to representation object
 */
public class Application {

    public static void main(String[] args){
        HashUtil hashUtil = new HashUtil();
//      Initiating Objects and Variables
        int KEY_LENGTH = 1024;
        RSAService rsaService = new RSAService(KEY_LENGTH);
        BigInteger message = new BigInteger("21483");
        System.out.println(String.format("Message :%s\n", message));

        // RSA
        // Key generation
        // Profiling point
        RSAModel keyPair = rsaService.generateKeyPair();
        // End of profiling point

        // Encryption - Decryption
        // Profiling point
        BigInteger encrypted = rsaService.encrypt(message, keyPair);
        BigInteger decrypted = rsaService.decrypt(encrypted, keyPair);
        // End of Profiling point

        // Signing and Verify Signature
        // Profiling point
        BigInteger signature = rsaService.signSignature(message, keyPair);
        Boolean verifyResult = rsaService.verifySignature(message, signature, keyPair);
        // End of Profiling point

        // Logging
        System.out.println(String.format("Hashed :%s\n", message));
        System.out.println(String.format("-- KeyPair --\n%s", keyPair.toString()));
        System.out.println(String.format("-- RSA Params --\n%s", rsaService.toString()));
        System.out.println(String.format("Message : %s", message.toString()));
        System.out.println(String.format("Encrypted : %s", encrypted.toString()));
        System.out.println(String.format("Decrypted : %s", decrypted.toString()));
        System.out.println(String.format("Signature : %s", signature.toString()));
        System.out.println(String.format("Verify Result : %s", verifyResult.toString()));
        // End of Logging
    }

}
