import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class PemUtils {
    // This class contains 4 static methods to write and read
    // RSA public and private keys.
    // The PEM format uses Base64 encoding, which is available in Java 8.
    // Written by Luc Longpre for Computer Security, Spring 2018   

    static void writePublicKey(PublicKey pubKey, String fileName)
            throws FileNotFoundException {
        File file = new File(fileName);
        // The new java construct, try with resource ...
        try (PrintWriter fw = new PrintWriter(file)) {
            fw.println("-----BEGIN PUBLIC KEY-----");
            String keyStr = Base64.getEncoder().encodeToString(pubKey.getEncoded());
            // Separating at 64 characters per line is not necessary,
            // but is more readable
            for (int i = 0; i < keyStr.length(); i += 64) {
                fw.println(keyStr.substring(i, Integer.min(keyStr.length(), i + 64)));
            }
            fw.println("-----END PUBLIC KEY-----");
            fw.close();
        }
    }

    static PublicKey readPublicKey(String fileName) {
        File file;
        StringBuilder contents = new StringBuilder();
        PublicKey pKey = null;
        try {
            file = new File(fileName);
            Scanner input = new Scanner(file);
            String line = input.nextLine();
            if (!"-----BEGIN PUBLIC KEY-----".equals(line)) {
                System.out.println("expecting:-----BEGIN PUBLIC KEY-----");
                System.out.println("got:" + line);
            } else {
                line = input.nextLine();
                while (!"-----END PUBLIC KEY-----".equals(line)) {
                    contents.append(line);
                    line = input.nextLine();
                }
            }
            input.close();
        } catch (Exception e) {
            System.out.println("Could not open key file");
            return null;
        }
        byte[] keyBytes = Base64.getDecoder().decode(contents.toString());
        X509EncodedKeySpec spec
                = new X509EncodedKeySpec(keyBytes);
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            pKey = kf.generatePublic(spec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.out.println("public key recovery exception");
            return null;
        }
        return pKey;
    }

    static PublicKey constructPublicKey(String pubKeyString) {
        String contents = "";
        PublicKey pKey = null;
        try {
            Scanner input = new Scanner(pubKeyString);
            String line = input.nextLine();
            if (!"-----BEGIN PUBLIC KEY-----".equals(line)) {
                System.out.println("expecting:-----BEGIN PUBLIC KEY-----");
                System.out.println("got:" + line);
            } else {
                line = input.nextLine();
                while (!"-----END PUBLIC KEY-----".equals(line)) {
                    contents += line;
                    line = input.nextLine();
                }
            }
            input.close();
        } catch (Exception e) {
            System.out.println("Could not open key file");
            return null;
        }
        byte[] keyBytes = Base64.getDecoder().decode(contents);
        X509EncodedKeySpec spec
                = new X509EncodedKeySpec(keyBytes);
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            pKey = kf.generatePublic(spec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.out.println("public key recovery exception");
            return null;
        }
        return pKey;
    }

    static void writePrivateKey(PrivateKey pubKey, String fileName)
            throws FileNotFoundException {
        File file = new File(fileName);
        PrintWriter fw = new PrintWriter(file);
        fw.println("-----BEGIN PRIVATE KEY-----");
        String keyStr = Base64.getEncoder().encodeToString(pubKey.getEncoded());
        // Separating at 64 characters per line is not necessary,
        // but is more readable
        for (int i = 0; i < keyStr.length(); i += 64) {
            fw.println(keyStr.substring(i, Integer.min(keyStr.length(), i + 64)));
        }
        fw.println("-----END PRIVATE KEY-----");
        fw.close();
    }

    static PrivateKey readPrivateKey(String fileName) {
        File file;
        StringBuilder contents = new StringBuilder();
        PrivateKey prKey = null;
        try {
            file = new File(fileName);
            Scanner input = new Scanner(file);
            String line = input.nextLine();
            if (!"-----BEGIN PRIVATE KEY-----".equals(line)) {
                System.out.println("File format error");
            } else {
                line = input.nextLine();
                while (!"-----END PRIVATE KEY-----".equals(line)) {
                    contents.append(line);
                    line = input.nextLine();
                }
            }
            input.close();
        } catch (Exception e) {
            System.out.println("Could not open file");
        }
        byte[] keyBytes = Base64.getDecoder().decode(contents.toString());
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            prKey = kf.generatePrivate(spec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.out.println(e);
        }
        return prKey;
    }
}
