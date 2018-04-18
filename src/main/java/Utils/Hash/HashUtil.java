package Utils.Hash;

import Utils.Exception.UserException;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/*
    Mas Eka Setiawan - <mas.eka@ui.ac.id>
    Computer Engineering, University of Indonesia
    Benchmarking RSA and ECDSA Algorithm
*/

public class HashUtil {

    public enum AlgorithmID {

        // Enumeration of AlgorithmID based on Java Cryptography Architecture Standard Algorithm Name Documentation
        // [4/15/18] https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#MessageDigest

        MD2("MD2"),
        MD5("MD5"),
        SHA_1("SHA-1"),
        SHA_256("SHA-256"),
        SHA_384("SHA-384"),
        SHA_512("SHA-512");

        String algorithmId;

        AlgorithmID(String algorithmId){
            this.algorithmId = algorithmId;
        }

        @Override
        public String toString(){
            return this.algorithmId;
        }

    }

    public BigInteger digest(BigInteger message, AlgorithmID algorithmId){
        try {
            MessageDigest messageDigest = java.security.MessageDigest.getInstance(algorithmId.toString());
            messageDigest.update(message.toByteArray(), 0, message.toByteArray().length);
            return new BigInteger(1, messageDigest.digest());
        } catch(NoSuchAlgorithmException e){
            throw new UserException("Algorithm not found");
        }
    }

}
