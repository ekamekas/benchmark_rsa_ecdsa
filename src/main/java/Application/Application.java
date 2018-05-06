package Application;

import Model.ECDSA.ECDSAModel;
import Model.ECDSA.PointModel;
import Model.ECDSA.SignatureModel;
import Model.RSA.RSAModel;
import Service.ECDSA.ECDSAService;
import Service.RSA.RSAService;

import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.MemoryUsage;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import Utils.Hash.HashUtil;

/*
    Mas Eka Setiawan - <mas.eka@ui.ac.id>
    Computer Engineering, University of Indonesia
    Benchmarking RSA and ECDSA Algorithm
*/

/*
    TODO:
    > Create looped test environment to take the data
    > Inject benchmarking code/framework to measure resource allocation (CPU/Memory)
    > Export the data into file or to representation object
*/
public class Application {

    final static int COUNT_LOOP = 10;
    final static int EPOCH_THRESHOLD_MINUTE = 60000;
    final static int MESSAGE_LENGTH = 256;  // Emulate AES_ENCRYPTED KEY

    public static void main(String[] args){

        /*
            Perbandingan keylength ECDSA dan RSA*
                ECC     |   RSA
                160     |   1024
                224     |   2048
                256     |   3072
                384     |   7680
                512     |   15360

            *sumber :
             NIST, "Block Cipher Techniques," 29 11 2017. [Online]. Available: https://csrc.nist.gov/Projects/Block-Cipher-Techniques
         */

//        final int KEY_LENGTH = 1024;
//        final ECDSAService.AlgorithmID ALGORITHM_ID = ECDSAService.AlgorithmID.SECP_224k1;
        BigInteger message = new BigInteger(MESSAGE_LENGTH, new SecureRandom());
//        System.out.println(String.format("Message :%s\n", message));

        // RSA initiation
//        int loop = 0;
//        do {
//        RSAService rsaService = new RSAService(KEY_LENGTH);
//        RSAModel keyPair = rsaService.generateKeyPair();
//        BigInteger encrypted = rsaService.encrypt(message, keyPair);
//        BigInteger decrypted = rsaService.decrypt(encrypted, keyPair);
//        BigInteger signature = rsaService.signSignature(message, keyPair);
//        Boolean rsaVerify = rsaService.verifySignature(message, signature, keyPair);

            // ECDSA initiation
//        ECDSAService ecdsaService = new ECDSAService(ALGORITHM_ID);
//        ECDSAModel ecdsaKeyPair = ecdsaService.generateKeyPair();
//        SignatureModel ecdsaSignature = ecdsaService.signSignature(message, ecdsaKeyPair);
//        Boolean ecdsaVerify = ecdsaService.messageVerify(message, ecdsaSignature, ecdsaKeyPair);
//            loop+=1;
//        }while(loop <= COUNT_LOOP);
//        RSAService rsaService = new RSAService(KEY_LENGTH);
//        RSAModel keyPair = rsaService.generateKeyPair();
//        BigInteger encrypted = rsaService.encrypt(message, keyPair);
//        BigInteger decrypted = rsaService.decrypt(encrypted, keyPair);
//        BigInteger signature = rsaService.signSignature(message, keyPair);
//        Boolean rsaVerify = rsaService.verifySignature(message, signature, keyPair);

        // ECDSA initiation
//        ECDSAService ecdsaService = new ECDSAService(ALGORITHM_ID);
//        ECDSAModel ecdsaKeyPair = ecdsaService.generateKeyPair();
//        SignatureModel ecdsaSignature = ecdsaService.signSignature(message, ecdsaKeyPair);
//        Boolean ecdsaVerify = ecdsaService.messageVerify(message, ecdsaSignature, ecdsaKeyPair);

        // Testing environment
//        System.out.println(String.format("[%s] %s", new Date().toString(), "Start testing"));
//        HashMap<String, List<String>> testResult = new HashMap<>();
        // Process per minute test
//        System.out.println(
//                String.format("[%s] %s", new Date().toString(), "Start process per minute test"));
//        testResult.putAll(processPerMinute(
//                1024, ECDSAService.AlgorithmID.SECP_192r1, EPOCH_THRESHOLD_MINUTE, message));
//        testResult.putAll(processPerMinute(
//                2048, ECDSAService.AlgorithmID.SECP_224r1, EPOCH_THRESHOLD_MINUTE, message));
//        testResult.putAll(processPerMinute(
//                3072, ECDSAService.AlgorithmID.SECP_256r1, EPOCH_THRESHOLD_MINUTE, message));
//        testResult.putAll(processPerMinute(
//                7680, ECDSAService.AlgorithmID.SECP_384r1, EPOCH_THRESHOLD_MINUTE, message));
//        testResult.putAll(processPerMinute(
//                15360, ECDSAService.AlgorithmID.SECP_521r1, EPOCH_THRESHOLD_MINUTE, message));
//        System.out.println(
//                String.format("[%s] %s", new Date().toString(), "End of process per minute test"));
        // End of process per minute test
        // Memory allocation test
        // End of memory allocation
        // CPU utilization test
        // End of CPU utilization test
        // Resource test - this test use profiling agent
//        System.out.println(String.format("[%s] %s", new Date().toString(), "Start resource test"));
//        resourceTest(1024, ECDSAService.AlgorithmID.SECP_192r1, EPOCH_THRESHOLD_MINUTE, message);
//       resourceTest(2048, ECDSAService.AlgorithmID.SECP_224r1, EPOCH_THRESHOLD_MINUTE, message);
        resourceTest(3072, ECDSAService.AlgorithmID.SECP_256r1, EPOCH_THRESHOLD_MINUTE, message);
//        resourceTest(7680, ECDSAService.AlgorithmID.SECP_384r1, EPOCH_THRESHOLD_MINUTE, message);
//         resourceTest(15360, ECDSAService.AlgorithmID.SECP_521r1, EPOCH_THRESHOLD_MINUTE, message);
//        System.out.println(String.format("[%s] %s", new Date().toString(), "End of resource test"));
        // End of resource test
//        System.out.println(String.format("[%s] %s", new Date().toString(), "End of testing"));
        // End of testing environment

//        System.out.println(testResult);

        // Logging
//        System.out.println(String.format("----- RSA -----"));
//        System.out.println(String.format("-- KeyPair --\n%s", keyPair.toString()));
//        System.out.println(String.format("-- RSA Params --\n%s", rsaService.toString()));
//        System.out.println(String.format("Message : %s", message.toString()));
//        System.out.println(String.format("Encrypted : %s", encrypted.toString()));
//        System.out.println(String.format("Decrypted : %s", decrypted.toString()));
//        System.out.println(String.format("Signature : %s", signature.toString()));
//        System.out.println(String.format("Verify Result : %s", rsaVerify.toString()));
//
//        System.out.println(String.format("\n----- ECDSA -----"));
//        System.out.println(String.format("-- KeyPair --"));
//        System.out.println(String.format("Private key\n%s", ecdsaKeyPair.getPrivateKey()));
//        System.out.println(String.format("Public key\n%s", ecdsaKeyPair.getPublicKey()));
//        System.out.println(String.format("-- ECDSA Params --\n%s", ecdsaKeyPair.toString()));
//        System.out.println(String.format("Message : %s", message.toString()));
//        System.out.println(String.format("Signature : %s", ecdsaSignature));
//        System.out.println(String.format("Verify Result : %s", ecdsaVerify));
        // End of Logging
    }

    private static List cpuUtilizationTest(
            int KEY_LENGTH, ECDSAService.AlgorithmID ALGORITHM_ID, int EPOCH_THRESHOLD_MINUTE)
    {
        List cpuTimeList = new ArrayList();

        return cpuTimeList;
    }

    private static void resourceTest(
            int KEY_LENGTH, ECDSAService.AlgorithmID ALGORITHM_ID, int EPOCH_THRESHOLD_MINUTE, BigInteger message)
    {

            HashMap<String, List<String>> result = new HashMap<>();
//            final String rsaKeyGenerationLabel = String.format("%s-%s-%s","rsa","keygen",String.valueOf(KEY_LENGTH));
//            final String rsaSignatureLabel = String.format("%s-%s-%s","rsa","sig",String.valueOf(KEY_LENGTH));
//            final String rsaVerifyLabel = String.format("%s-%s-%s","rsa","ver",String.valueOf(KEY_LENGTH));
//            final String ecdsaKeyGenerationLabel = String.format("%s-%s-%s","ecdsa","keygen",ALGORITHM_ID.toString());
//            final String ecdsaSignatureLabel = String.format("%s-%s-%s","ecdsa","sig",ALGORITHM_ID.toString());
//            final String ecdsaVerifyLabel = String.format("%s-%s-%s","ecdsa","ver",ALGORITHM_ID.toString());
//            MemoryMXBean mbean = ManagementFactory.getMemoryMXBean();
//            long memusageBeforeProcess;
//            long memusageAfterProcess;
            // RSA initiation

            // memusageBeforeProcess = mbean.getHeapMemoryUsage().getUsed();
             RSAService rsaService = new RSAService(KEY_LENGTH);
             RSAModel keyPair = rsaService.generateKeyPair();
        //    memusageAfterProcess = mbean.getHeapMemoryUsage().getUsed();
//            System.out.println(String.format("%s : [MEMORY] %dB", rsaKeyGenerationLabel, memusageAfterProcess - memusageBeforeProcess));

//            BigInteger encrypted = rsaService.encrypt(message, keyPair);
//            BigInteger decrypted = rsaService.decrypt(encrypted, keyPair);

//            memusageBeforeProcess = mbean.getHeapMemoryUsage().getUsed();
             BigInteger signature = rsaService.signSignature(message, keyPair);
//            memusageAfterProcess = mbean.getHeapMemoryUsage().getUsed();
            System.out.println(String.format("RSA : %d", signature.bitLength()));
//            System.out.println(String.format("%s : [MEMORY] %dB", rsaSignatureLabel, memusageAfterProcess - memusageBeforeProcess));

//            memusageBeforeProcess = mbean.getHeapMemoryUsage().getUsed();
             Boolean rsaVerify = rsaService.verifySignature(message, signature, keyPair);
            // memusageAfterProcess = mbean.getHeapMemoryUsage().getUsed();
//            System.out.println(String.format("%s : [MEMORY] %dB", rsaVerifyLabel, memusageAfterProcess - memusageBeforeProcess));
            // System.out.println(String.format("[MEMORY] %d B",memusageAfterProcess - memusageBeforeProcess));

//            System.out.println(new Date().toString());
            // System.gc();
//            try {
//                TimeUnit.MINUTES.sleep(1);
//            } catch (InterruptedException e){
//
//            }

            // ECDSA initiation
//            memusageBeforeProcess = mbean.getHeapMemoryUsage().getUsed();
            ECDSAService ecdsaService = new ECDSAService(ALGORITHM_ID);
            ECDSAModel ecdsaKeyPair = ecdsaService.generateKeyPair();
//            memusageAfterProcess = mbean.getHeapMemoryUsage().getUsed();
//            System.out.println(String.format("%s : [MEMORY] %dB", ecdsaKeyGenerationLabel, memusageAfterProcess - memusageBeforeProcess));

//            memusageBeforeProcess = mbean.getHeapMemoryUsage().getUsed();
            SignatureModel ecdsaSignature = ecdsaService.signSignature(message, ecdsaKeyPair);
            System.out.println(String.format("ECDSA : %d", ecdsaSignature.getR().bitLength() + ecdsaSignature.getS().bitLength()));
//            memusageAfterProcess = mbean.getHeapMemoryUsage().getUsed();
//            System.out.println(String.format("%s : [MEMORY] %dB", ecdsaSignatureLabel, memusageAfterProcess - memusageBeforeProcess));

//            memusageBeforeProcess = mbean.getHeapMemoryUsage().getUsed();
            Boolean ecdsaVerify = ecdsaService.messageVerify(message, ecdsaSignature, ecdsaKeyPair);
//            memusageAfterProcess = mbean.getHeapMemoryUsage().getUsed();
//            System.out.println(String.format("%s : [MEMORY] %dB", ecdsaVerifyLabel, memusageAfterProcess - memusageBeforeProcess));
//            System.out.println(String.format("[MEMORY] %d B",memusageAfterProcess - memusageBeforeProcess));
    }

    private static List memUtilizationTest(
            int KEY_LENGTH, ECDSAService.AlgorithmID ALGORITHM_ID, int EPOCH_THRESHOLD_MINUTE, BigInteger message)
    {
        List memAllocationList = new ArrayList();
        return memAllocationList;
    }

    private static HashMap<String, List<String>> processPerMinute(
            int KEY_LENGTH, ECDSAService.AlgorithmID ALGORITHM_ID, int EPOCH_THRESHOLD_MINUTE, BigInteger message)
    {

        HashMap<String, List<String>> result = new HashMap<>();
        final String rsaKeyGenerationLabel = String.format("%s-%s-%s","rsa","keygen",String.valueOf(KEY_LENGTH));
        final String rsaSignatureLabel = String.format("%s-%s-%s","rsa","sig",String.valueOf(KEY_LENGTH));
        final String rsaVerifyLabel = String.format("%s-%s-%s","rsa","ver",String.valueOf(KEY_LENGTH));
        final String ecdsaKeyGenerationLabel = String.format("%s-%s-%s","ecdsa","keygen",ALGORITHM_ID.toString());
        final String ecdsaSignatureLabel = String.format("%s-%s-%s","ecdsa","sig",ALGORITHM_ID.toString());
        final String ecdsaVerifyLabel = String.format("%s-%s-%s","ecdsa","ver",ALGORITHM_ID.toString());

        // RSA initiation
        RSAService rsaService = new RSAService(KEY_LENGTH);
        RSAModel keyPair = rsaService.generateKeyPair();
        BigInteger signature = rsaService.signSignature(message, keyPair);
        Boolean rsaVerify = rsaService.verifySignature(message, signature, keyPair);

        // ECDSA initiation
        ECDSAService ecdsaService = new ECDSAService(ALGORITHM_ID);
        ECDSAModel ecdsaKeyPair = ecdsaService.generateKeyPair();
        SignatureModel ecdsaSignature = ecdsaService.signSignature(message, ecdsaKeyPair);
        Boolean ecdsaVerify = ecdsaService.messageVerify(message, ecdsaSignature, ecdsaKeyPair);

        // RSA
        // Key generation
        // Profiling point
        System.out.println(String.format("[%s] %s", new Date().toString(), "START RSA - Generate keyPair"));
        List countLoopList = new ArrayList();
        for(int index = 0; index < COUNT_LOOP; index++){
            long countLoop = 0;
            long endEpoch = System.currentTimeMillis() + EPOCH_THRESHOLD_MINUTE;
            do {
                new RSAService(KEY_LENGTH).generateKeyPair();
                countLoop++;
            } while(System.currentTimeMillis() < endEpoch);
            countLoopList.add(countLoop);
        }
        result.put(rsaKeyGenerationLabel, countLoopList);
        System.out.println(String.format("Count : %s", countLoopList.toString()));
        System.out.println(String.format("[%s] %s", new Date().toString(), "END RSA - Generate keyPair"));
        // End of profiling point

        // Encryption - Decryption
        // Profiling point
        BigInteger encrypted = rsaService.encrypt(message, keyPair);
        BigInteger decrypted = rsaService.decrypt(encrypted, keyPair);
        // End of Profiling point

        // Signing
        // Profiling point
        System.out.println(String.format("[%s] %s", new Date().toString(), "START RSA - Generate signature"));
        countLoopList = new ArrayList();
        for(int index = 0; index < COUNT_LOOP; index++){
            long countLoop = 0;
            long endEpoch = System.currentTimeMillis() + EPOCH_THRESHOLD_MINUTE;
            do {
                rsaService.signSignature(message, keyPair);
                countLoop++;
            } while(System.currentTimeMillis() < endEpoch);
            countLoopList.add(countLoop);
        }
        result.put(rsaSignatureLabel, countLoopList);
        System.out.println(String.format("Count : %s", countLoopList.toString()));
        System.out.println(String.format("[%s] %s", new Date().toString(), "END RSA - Generate signature"));
        // End of profiling point

        // Verify Signature
        // Profiling point
        System.out.println(String.format("[%s] %s", new Date().toString(), "START RSA - Verify signature"));
        countLoopList = new ArrayList();
        for(int index = 0; index < COUNT_LOOP; index++){
            long countLoop = 0;
            long endEpoch = System.currentTimeMillis() + EPOCH_THRESHOLD_MINUTE;
            do {
                rsaService.verifySignature(message, signature, keyPair);
                countLoop++;
            } while(System.currentTimeMillis() < endEpoch);
            countLoopList.add(countLoop);
        }
        result.put(rsaVerifyLabel, countLoopList);
        System.out.println(String.format("Count : %s", countLoopList.toString()));
        System.out.println(String.format("[%s] %s", new Date().toString(), "END RSA - Verify signature"));
        // End of Profiling point

        // End of RSA

        // ECDSA
        // Key generation
        // Profiling point
        System.out.println(String.format("[%s] %s", new Date().toString(), "START ECDSA - Generate keyPair"));
        countLoopList = new ArrayList();
        for(int index = 0; index < COUNT_LOOP; index++){
            long countLoop = 0;
            long endEpoch = System.currentTimeMillis() + EPOCH_THRESHOLD_MINUTE;
            do {
                new ECDSAService(ALGORITHM_ID).generateKeyPair();
                countLoop++;
            } while(System.currentTimeMillis() < endEpoch);
            countLoopList.add(countLoop);
        }
        result.put(ecdsaKeyGenerationLabel, countLoopList);
        System.out.println(String.format("Count : %s", countLoopList.toString()));
        System.out.println(String.format("[%s] %s", new Date().toString(), "END ECDSA - Generate keyPair"));
        // End of profiling point

        // Signing
        // Profiling point
        System.out.println(String.format("[%s] %s", new Date().toString(), "START ECDSA - Generate signature"));
        countLoopList = new ArrayList();
        for(int index = 0; index < COUNT_LOOP; index++){
            long countLoop = 0;
            long endEpoch = System.currentTimeMillis() + EPOCH_THRESHOLD_MINUTE;
            do {
                ecdsaService.signSignature(message, ecdsaKeyPair);
                countLoop++;
            } while(System.currentTimeMillis() < endEpoch);
            countLoopList.add(countLoop);
        }
        result.put(ecdsaSignatureLabel, countLoopList);
        System.out.println(String.format("Count : %s", countLoopList.toString()));
        System.out.println(String.format("[%s] %s", new Date().toString(), "END ECDSA - Generate signature"));
        // End of profiling point

        // Verify signature
        // Profiling point
        System.out.println(String.format("[%s] %s", new Date().toString(), "START ECDSA - Verfiy signature"));
        countLoopList = new ArrayList();
        for(int index = 0; index < COUNT_LOOP; index++){
            long countLoop = 0;
            long endEpoch = System.currentTimeMillis() + EPOCH_THRESHOLD_MINUTE;
            do {
                ecdsaService.messageVerify(message, ecdsaSignature, ecdsaKeyPair);
                countLoop++;
            } while(System.currentTimeMillis() < endEpoch);
            countLoopList.add(countLoop);
        }
        result.put(ecdsaVerifyLabel, countLoopList);
        System.out.println(String.format("Count : %s", countLoopList.toString()));
        System.out.println(String.format("[%s] %s", new Date().toString(), "END ECDSA - Verify signature"));
        // End of profiling point
        // End of ECDSA

        return result;

    }

    private static void wait(int second){
        Long endEpoch = System.currentTimeMillis() + second*1000;
        while (System.currentTimeMillis() < endEpoch);
    }

}
