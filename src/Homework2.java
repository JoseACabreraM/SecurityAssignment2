import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class Homework2 {

    private static KeyPair generateKeyPair() {
        KeyPair key = null;
        // generate key pair
        try {
            // Initialize a key pair generator
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            keyGen.initialize(1024, random);
            // Generate a key pair
            key = keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            // If no provider supports RSA, or the key size is not supported
            System.out.println("Key pair generator failed to generate keys, " + e);
        }
        return key;
    }

    private static void part1() {
        KeyPair clientKey1 = generateKeyPair();
        KeyPair clientKey2 = generateKeyPair();
        KeyPair serverKey1 = generateKeyPair();
        KeyPair serverKey2 = generateKeyPair();

        CreatePemKeys.writePrivateKey(clientKey1.getPrivate(), "jacmClientPrivateKey1.pem");
        CreatePemKeys.writePublicKey(clientKey1.getPublic(), "jacmClientPublicKey1.pem");
        CreatePemKeys.writePrivateKey(clientKey2.getPrivate(), "jacmClientPrivateKey2.pem");
        CreatePemKeys.writePublicKey(clientKey2.getPublic(), "jacmClientPublicKey2.pem");
        CreatePemKeys.writePrivateKey(serverKey1.getPrivate(), "jacmServerPrivateKey1.pem");
        CreatePemKeys.writePublicKey(serverKey1.getPublic(), "jacmServerPublicKey1.pem");
        CreatePemKeys.writePrivateKey(serverKey2.getPrivate(), "jacmServerPrivateKey2.pem");
        CreatePemKeys.writePublicKey(serverKey2.getPublic(), "jacmServerPublicKey2.pem");
    }

    public static void main(String[] args) {

        part1();
    }


}
