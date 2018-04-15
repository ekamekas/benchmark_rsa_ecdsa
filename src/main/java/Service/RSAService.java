package Service;

import Model.RSA.*;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

public class RSAService {

    private BigInteger primeP;      // Random big prime number
    private BigInteger primeQ;      // Random big prime number
    private BigInteger modulusN;    // Product of primeP and primeQ
    private BigInteger eulerPhi;    // Euler's totient function
    private int KEY_LENGTH;         // Desired length of generated keys
    private BigInteger coprimeE = new BigInteger("65537");    // Calculation result CoprimeE for encryption
    private BigInteger exponentD;   // Calculation result invervse for decryption
    private RSAModel rsaModel = new RSAModel();
    private Random random;          // Random value for salting

    public RSAService(int keyLength){
        this.KEY_LENGTH = keyLength;
        this.random = new SecureRandom();
        this.primeP = BigInteger.probablePrime(this.KEY_LENGTH / 2, this.random);
        this.primeQ = BigInteger.probablePrime(this.KEY_LENGTH / 2, this.random);
        this.modulusN = this.primeP.multiply(this.primeQ);
    }

    public RSAService(BigInteger primeP, BigInteger primeQ, int keyLength){
        this.KEY_LENGTH = keyLength;
        this.random = new SecureRandom();
        this.primeP = primeP;
        this.primeQ = primeQ;
        this.modulusN = this.primeP.multiply(this.primeQ);
    }

    public RSAModel generateKeyPair(){
        BigInteger totientFunction = eulerTotientFunction(this.primeP, this.primeQ);
        Map<String, BigInteger> keyPair = generateKeyPair(totientFunction);

        this.rsaModel.setPublicKey(new PublicKeyModel(keyPair.get("public"), this.modulusN));
        this.rsaModel.setPrivateKey(new PrivateKeyModel(keyPair.get("private"), this.modulusN));
        return rsaModel;
    }

    public BigInteger encrypt(BigInteger message, RSAModel rsaModel){
        return message.modPow(rsaModel.getPublicKey().getCoprimeE(), rsaModel.getPublicKey().getModulusN());
    }

    public BigInteger decrypt(BigInteger message, RSAModel rsaModel){
        return message.modPow(rsaModel.getPrivateKey().getExponentD(), rsaModel.getPrivateKey().getModulusN());
    }

//    Getter and Setter
    public void setRSAModel(RSAModel rsaModel){
        this.rsaModel = rsaModel;
    }

    public RSAModel getRsaModel(){
        return this.rsaModel;
    }

//  Utils function
    public Map<String, BigInteger> generateKeyPair(BigInteger eulerPhi){
        Map<String, BigInteger> keyPair = new HashMap<>();
        do{
            this.coprimeE = new BigInteger(eulerPhi.bitLength(), this.random);
        } while (this.coprimeE.compareTo(BigInteger.ONE) <= 0
                || this.coprimeE.compareTo(eulerPhi) >= 0
                || !this.coprimeE.gcd(eulerPhi).equals(BigInteger.ONE));
//        this.coprimeE = new BigInteger("65537");
        this.exponentD = this.coprimeE.modInverse(eulerPhi);
        keyPair.put("public", this.coprimeE);
        keyPair.put("private", this.exponentD);
        return keyPair;
    }

    public BigInteger eulerTotientFunction(BigInteger primeP, BigInteger primeQ){
        return primeP.subtract(BigInteger.ONE).multiply(primeQ.subtract(BigInteger.ONE));
    }

    // Euler GCD
    public BigInteger gcd(BigInteger numberA, BigInteger numberB){
        while(numberA.compareTo(numberB) > 0){
            if (numberA.compareTo(numberB) > numberB.intValue()){
                numberA.equals(numberA.mod(numberB));
            }else{
                numberB.equals(numberB.mod(numberA));
            }
        }
        return numberA.max(numberB);
    }

    // Euler LCM
    public BigInteger lcm(BigInteger numberA, BigInteger numberB){
        return ((numberA.multiply(numberB)).divide(gcd(numberA,numberB)));
    }

    // Convert byte[] to string
    public String bytesToString(byte[] byteArray){
        String converted = "";
        for(byte byteItem : byteArray){
            converted += new String(Byte.toString(byteItem));
        }
        return converted;
    }

    @Override
    public String toString(){
        return String.format("P : %s\nQ : %s\nKey Size : %d\nPhi : %s",
                this.primeP.toString(),
                this.primeQ.toString(),
                this.KEY_LENGTH,
                this.eulerTotientFunction(this.primeP, this.primeQ).toString());
    }

}
