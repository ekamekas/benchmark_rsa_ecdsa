package Service.ECDSA;

import Model.ECDSA.ECDSAModel;
import Model.ECDSA.PointModel;
import Model.ECDSA.SignatureModel;
import Utils.Exception.UserException;
import Utils.Hash.HashUtil;

import java.math.BigInteger;
import java.security.SecureRandom;

/*
    Mas Eka Setiawan - <mas.eka@ui.ac.id>
    Computer Engineering, University of Indonesia
    Benchmarking RSA and ECDSA Algorithm
*/

/*
    TODO:
    // Test signature method
    // Test verify method
 */
public class ECDSAService {

    public enum AlgorithmID{

        SECP_192k1("SECP_192k1",192,
                new BigInteger("6277101735386680763835789423207666416102355444459739541047"),
                new BigInteger("6277101735386680763835789423061264271957123915200845512077"),
                new BigInteger("00000000000000000000000000000000000000000000001"),
                new BigInteger("00000000000000000000000000000000000000000000000"),
                new BigInteger("00000000000000000000000000000000000000000000003"),
                new PointModel(new BigInteger("53775212622912263251985501180552567363229037935769709693"), new BigInteger("385108391982600717572440947423858335415441070543209377693"))),
        SECP_192r1("SECP_192r1",192,
                new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF", 16),
                new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831",16),
                new BigInteger("00000000000000000000000000000000000000000000001"),
                new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC", 16),
                new BigInteger("64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1", 16),
                new PointModel(new BigInteger("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", 16), new BigInteger("07192B95FFC8DA78631011ED6B24CDD573F977A11E794811",16)),
                new BigInteger("3045AE6FC8422F64ED579528D38120EAE12196D5", 16)),
        SECP_224k1("SECP_224k1",224,
                new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFE56D",16),
                new BigInteger("010000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7",16),
                new BigInteger("00000000000000000000000000000000000000000000001"),
                new BigInteger("00000000000000000000000000000000000000000000000000000000",16),
                new BigInteger("00000000000000000000000000000000000000000000000000000005",16),
                new PointModel(new BigInteger("A1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C",16), new BigInteger("7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5",16))),
        SECP_224r1("SECP_224r1",224,
                new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001", 16),
                new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D",16),
                new BigInteger("00000000000000000000000000000000000000000000001"),
                new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE", 16),
                new BigInteger("B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4", 16),
                new PointModel(new BigInteger("B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21", 16), new BigInteger("BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34",16)),
                new BigInteger("BD71344799D5C7FCDC45B59FA3B9AB8F6A948BC5", 16)),
        SECP_256k1("SECP_256k1",256,
                new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",16),
                new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",16),
                new BigInteger("00000000000000000000000000000000000000000000001"),
                new BigInteger("0000000000000000000000000000000000000000000000000000000000000000",16),
                new BigInteger("0000000000000000000000000000000000000000000000000000000000000007",16),
                new PointModel(new BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",16), new BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",16))),
        SECP_256r1("SECP_256r1",256,
                new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16),
                new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",16),
                new BigInteger("00000000000000000000000000000000000000000000001"),
                new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16),
                new BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16),
                new PointModel(new BigInteger("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16), new BigInteger("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",16)),
                new BigInteger("C49D360886E704936A6678E1139D26B7819F7E90", 16)),
        SECP_384r1("SECP_384r1",384,
                new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF", 16),
                new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",16),
                new BigInteger("00000000000000000000000000000000000000000000001"),
                new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC", 16),
                new BigInteger("B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF", 16),
                new PointModel(new BigInteger("AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7", 16), new BigInteger("3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",16)),
                new BigInteger("A335926AA319A27A1D00896A6773A4827ACDAC73", 16)),
        SECP_512r1("SECP_512r1",512,
                new BigInteger("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16),
                new BigInteger("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",16),
                new BigInteger("00000000000000000000000000000000000000000000001"),
                new BigInteger("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC", 16),
                new BigInteger("0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00", 16),
                new PointModel(new BigInteger("00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5", 16), new BigInteger("BD66011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",16)),
                new BigInteger("D09E8800291CB85396CC6717393284AAA0DA64BA", 16));

        private String algorithmId;
        private ECDSAModel ecdsaModel = new ECDSAModel();

        AlgorithmID(String algorithmId, int keyLength, BigInteger primeModulus, BigInteger primeOrder, BigInteger cofactor,
                    BigInteger coefficientA, BigInteger coefficientB, PointModel basePoint){
            this.algorithmId = algorithmId;
            this.ecdsaModel.setKeyLength(keyLength);
            this.ecdsaModel.setPrimeModulus(primeModulus);
            this.ecdsaModel.setPrimeOrder(primeOrder);
            this.ecdsaModel.setCofactor(cofactor);
            this.ecdsaModel.setCoefficientA(coefficientA);
            this.ecdsaModel.setCoefficientB(coefficientB);
            this.ecdsaModel.setBaseGenerator(basePoint);
        }

        AlgorithmID(String algorithmId, int keyLength, BigInteger primeModulus, BigInteger primeOrder, BigInteger cofactor,
                    BigInteger coefficientA, BigInteger coefficientB, PointModel basePoint, BigInteger seed){
            this.algorithmId = algorithmId;
            this.ecdsaModel.setKeyLength(keyLength);
            this.ecdsaModel.setPrimeModulus(primeModulus);
            this.ecdsaModel.setPrimeOrder(primeOrder);
            this.ecdsaModel.setCofactor(cofactor);
            this.ecdsaModel.setSeed(seed);
            this.ecdsaModel.setCoefficientA(coefficientA);
            this.ecdsaModel.setCoefficientB(coefficientB);
            this.ecdsaModel.setBaseGenerator(basePoint);
        }

        @Override
        public String toString(){
            return this.algorithmId;
        }

        public ECDSAModel toECDSAModel(){
            return this.ecdsaModel;
        }

    }

    ECDSAModel ecdsaModel;
    HashUtil hashUtil = new HashUtil();

    public ECDSAService(BigInteger primeModulus, BigInteger primeOrder,
                        BigInteger coefficientA, BigInteger coefficientB,
                        PointModel basePoint, BigInteger seed){

    }

    // Overloading
    public ECDSAService(ECDSAService.AlgorithmID algorithmID){
        this.ecdsaModel = algorithmID.toECDSAModel();
    }

    public ECDSAModel generateKeyPair(){
        ecdsaModel.setPrivateKey(BigInteger.probablePrime(ecdsaModel.getKeyLength(), new SecureRandom()));
        ecdsaModel.setPublicKey(pointMultiply(ecdsaModel.getBaseGenerator(), ecdsaModel.getPrimeOrder(), ecdsaModel.getCoefficientA(), ecdsaModel.getPrivateKey()));
        return this.ecdsaModel;
    }

    public SignatureModel signSignature(BigInteger message, ECDSAModel ecdsaModel) {
        SignatureModel result = new SignatureModel(BigInteger.ZERO, BigInteger.ZERO);
        BigInteger k, kInv, r, e, s;
        PointModel kG;

        do {
            do {
                k = BigInteger.valueOf(1);
                kG = pointMultiply(ecdsaModel.getBaseGenerator(), ecdsaModel.getPrimeOrder(), ecdsaModel.getCoefficientA(), k);
                r = kG.getX().mod(ecdsaModel.getPrimeOrder());
            } while (r.compareTo(BigInteger.ZERO) == 0);

            kInv = k.modInverse(ecdsaModel.getPrimeOrder());
            e = hashUtil.digest(message, HashUtil.AlgorithmID.SHA_1);
            s = (kInv.multiply(e.add(ecdsaModel.getPrivateKey().multiply(r)))).mod(ecdsaModel.getPrimeOrder());
        } while (s.compareTo(BigInteger.ZERO) == 0);

        result.setR(r);
        result.setS(s);
        return result;
    }

    public boolean messageVerify(BigInteger message, SignatureModel signature, ECDSAModel ecdsaModel) {
        BigInteger r = signature.getR();
        BigInteger s = signature.getS();

        if (r.compareTo(ecdsaModel.getPrimeOrder()) >= 0) {
            return false;
        }
        if (s.compareTo(ecdsaModel.getPrimeOrder()) >= 0) {
            return false;
        }

        BigInteger e = hashUtil.digest(message, HashUtil.AlgorithmID.SHA_1);
        BigInteger w = s.modInverse(ecdsaModel.getPrimeOrder());

        BigInteger u1 = (e.multiply(w)).mod(ecdsaModel.getPrimeOrder());
        BigInteger u2 = (r.multiply(w)).mod(ecdsaModel.getPrimeOrder());

        PointModel X = pointAddition(
                        pointMultiply(ecdsaModel.getBaseGenerator(), ecdsaModel.getPrimeOrder(), ecdsaModel.getCoefficientA(), u1),
                        pointMultiply(ecdsaModel.getPublicKey(), ecdsaModel.getPrimeOrder(), ecdsaModel.getCoefficientA(), u2),
                        ecdsaModel.getPrimeOrder());

        BigInteger v = X.getX().mod(ecdsaModel.getPrimeOrder());

        if (v.compareTo(r) == 0) {
            return true;
        }
        return false;
    }

    // Utils
    // Create E for hashing output > primeModulus
    public BigInteger calculateE(BigInteger primeOrder, BigInteger message){
        int primeOrderBitSize = primeOrder.bitLength();
        int messageBitSize = message.bitLength();

        BigInteger calculatedOrder = primeOrder;
        if(primeOrderBitSize < messageBitSize){
            calculatedOrder.shiftRight(messageBitSize - primeOrderBitSize);
        }

        return calculatedOrder;

    }

    // Validate ECDSA domain params
    public Boolean validateCurve(){

        if(null==this.ecdsaModel.getSeed())
            throw new UserException("ECDSA Model doesnt have seed");
        if(this.ecdsaModel.getSeed().bitLength() > 160)
            throw new UserException("ECDSA Model seed too long");

        return true;

    }

    // Point negation
    // Credit : name@github.com - <Repo>
    public PointModel pointNegation(PointModel pointModel) {
        PointModel result = new PointModel(BigInteger.ZERO, BigInteger.ZERO);
        result.setX(pointModel.getX());
        result.setY(pointModel.getY().multiply(BigInteger.valueOf(-1)));
        return result;
    }

    // Point negation
    // Credit : name@github.com - <Repo>
    public PointModel pointAddition(PointModel pointA, PointModel pointB, BigInteger primeOrder) {
        PointModel result = new PointModel(BigInteger.ZERO, BigInteger.ZERO);

        BigInteger y = (pointB.getY().subtract(pointA.getY()));
        BigInteger x = (pointB.getX().subtract(pointA.getX()));
        x = x.modInverse(primeOrder);
        y = y.multiply(x).mod(primeOrder);
        x = y.multiply(y);

        result.setX(((x.subtract(pointA.getX())).subtract(pointB.getX())).mod(primeOrder));
        result.setY((y.multiply(pointA.getY().subtract(x))).subtract(pointB.getY()).mod(primeOrder));

        return result;
    }

    // Point doubling
    // Credit : name@github.com - <Repo>
    public PointModel pointDoubling(PointModel pointModel, BigInteger n, BigInteger coefficientA) {
        PointModel result = new PointModel(BigInteger.ZERO, BigInteger.ZERO);

        BigInteger i = pointModel.getX().multiply(pointModel.getX()).multiply(BigInteger.valueOf(3)).add(coefficientA);
        BigInteger j = (pointModel.getY().multiply(BigInteger.valueOf(2))).modInverse(n);
        i = (i.multiply(j)).mod(n);
        j = i.multiply(i);

        result.setX((j.subtract(pointModel.getX().multiply(BigInteger.valueOf(2)))).mod(n));
        result.setY((i.multiply(pointModel.getX().subtract(j))).subtract(pointModel.getY()).mod(n));

        return result;
    }

    // Point doubling
    // Credit : name@github.com - <Repo>
    public PointModel pointMultiply(PointModel pointModel, BigInteger n, BigInteger a, BigInteger mult) {
        PointModel result = new PointModel(BigInteger.ZERO, BigInteger.ZERO);
        PointModel doubledPoint = pointModel;

        boolean set = false;
        String binMult = mult.toString(2);
        int binMultLen = binMult.length();

        for (int c=binMultLen-1; c>= 0; c--) {
            // System.out.print("|"+c+"|");
            if (binMult.charAt(c) == '1') {
                if (set) {
                    result = pointAddition(result, doubledPoint, n);
                } else {
                    result = doubledPoint;
                    set = true;
                }
            }
            doubledPoint = pointDoubling(doubledPoint, n, a);
        }
        return result;
    }

    // Point multiplication
    public PointModel scalarMultiplication(BigInteger scalar, PointModel point){
        // TODO:
        // Using doubleAndAdd algorithm
        PointModel result = new PointModel(BigInteger.ZERO, BigInteger.ZERO);
//        while(scalar.bitLength() != 0){
//            if(scalar.and(BigInteger.ONE).equals(BigInteger.ONE)) /* Add */;
//            // Multiply
//        }

        result.setX(result.getX().multiply(scalar));
        result.setY(result.getY().multiply(scalar));

        return result;
    }

}
