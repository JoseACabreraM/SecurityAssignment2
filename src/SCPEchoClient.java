import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.util.Random;
import java.util.Scanner;

public class SCPEchoClient {
    // This code includes socket code originally provided
    // by Dr. Yoonsik Cheon at least 10 years ago.
    // This version used for Computer Security, Spring 2018.
    public static void main(String[] args) {

        String host;
        Scanner userInput = new Scanner(System.in);
        if (args.length > 0) {
            host = args[0];
        } else {
            System.out.println("Enter the server's address: (IP address or \"localhost\" or \"cspl000.utep.edu\")");
            host = userInput.nextLine();
        }

        BufferedReader in; // for reading strings from socket
        PrintWriter out;   // for writing strings to socket
        ObjectInputStream objectInput;   // for reading objects from socket        
        ObjectOutputStream objectOutput; // for writing objects to socket
        Cipher cipherEnc, cipherDec; // To encrypt and decrypt messages to/from server
        byte[] clientRandomBytes, serverRandomBytes; // Byte arrays required to create the shared secret
        PublicKey[] serverPublicKeys; // Stores the server's public key after verifying the certificate
        Socket socket;

        // Handshake
        try {
            // socket initialization

            socket = new Socket(host, 8008);
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            out = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));
        } catch (IOException e) {
            System.out.println("socket initialization error");
            return;
        }

        // Send hello to server
        out.println("hello");
        out.flush();

        // Verify the server's certificate and retrieve its public keys
        serverPublicKeys = VerifyCert.vCert(in);

        // Read and send certificate to server
        try {
            File file = new File("clientCertificate.txt");
            Scanner input = new Scanner(file);
            String line;
            while (input.hasNextLine()) {
                line = input.nextLine();
                out.println(line);
            }
            out.flush();
        } catch (FileNotFoundException e) {
            System.out.println("certificate file not found");
            return;
        }

        try {
            // initialize object streams
            objectOutput = new ObjectOutputStream(socket.getOutputStream());
            objectInput = new ObjectInputStream(socket.getInputStream());
            // receive encrypted random bytes from server
            byte[] encryptedBytes = (byte[]) objectInput.readObject();
            // receive signature of hash of random bytes from server
            byte[] signatureBytes = (byte[]) objectInput.readObject();
            PrivateKey clientPrivateKeyEnc = PemUtils.readPrivateKey("jacmClientPrivateKey1.pem"); // Client Encryption Private Key
            serverRandomBytes = Decrypt.decrypt(clientPrivateKeyEnc, encryptedBytes); // Decrypt byte array, encrypted by the server with the client's public key
            // will need to verify the signature and decrypt the random bytes
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(serverRandomBytes); // Compute the SHA-256 of the decrypted bytes, to verify the certificate's signature
            assert serverPublicKeys != null;
            boolean serverCertificate = Verify.verify(serverPublicKeys[1], hash, signatureBytes); // Verify that the received data matches the server's signature
            if (serverCertificate) {
                System.out.println("Successfully Verified Server Identity!");
            } else {
                System.out.println("Failed To Verify Server Identity!");
                return;
            }
        } catch (IOException | NoSuchAlgorithmException | ClassNotFoundException ex) {
            System.out.println("Problem with receiving random bytes from server");
            return;
        }

        // generate random bytes for shared secret
        clientRandomBytes = new byte[8];
        // the next line would initialize the byte array to random values
        new Random().nextBytes(clientRandomBytes);

        try {
            byte[] encryptedBytes = Encrypt.encrypt(serverPublicKeys[0], clientRandomBytes); // Encrypt the client's random bytes with the server's encryption public key
            objectOutput.writeObject(encryptedBytes); // Send encrypted bytes to the server
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashedBytes = digest.digest(clientRandomBytes); // Hash the client's random bytes with SHA-256, to create the signature
            PrivateKey clientPrivateKeySig = PemUtils.readPrivateKey("jacmClientPrivateKey2.pem"); // Client Signature Private Key
            byte[] signature = Sign.sign(clientPrivateKeySig, hashedBytes); // Sign the hashed random bytes
            objectOutput.writeObject(signature); // Send signature to the server
        } catch (IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            System.out.println("error computing or sending the signature for random bytes");
            return;
        }

        // Initialize the shared secret with all zeroes
        // will need to generate from a combination of the server and 
        // the client random bytes generated
        byte[] sharedSecret = new byte[16];
        assert serverRandomBytes != null;
        System.arraycopy(serverRandomBytes, 0, sharedSecret, 0, 8);
        System.arraycopy(clientRandomBytes, 0, sharedSecret, 8, 8);
        SecretKeySpec secretKey = new SecretKeySpec(sharedSecret, "AES");
        try {
            // we will use AES encryption, CBC chaining and PCS5 block padding
            cipherEnc = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipherDec = Cipher.getInstance("AES/CBC/PKCS5Padding");
            // generate an AES key derived from randomBytes array
            cipherEnc.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] iv = cipherEnc.getIV();
            objectOutput.writeObject(iv);
        } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            System.out.println("error setting up the AES encryption");
            return;
        }
        try {
            // Encrypted communication
            System.out.println("Starting messages to the server. Type messages, type BYE to end");
            boolean done = false;
            while (!done) {
                // Read message from the user
                String userStr = userInput.nextLine();
                // Encrypt the message
                byte[] encryptedBytes = cipherEnc.doFinal(userStr.getBytes("UTF-8"));
                // Send encrypted message as an object to the server
                objectOutput.writeObject(encryptedBytes);
                // If user says "BYE", end session
                if (userStr.trim().equals("BYE")) {
                    System.out.println("client session ended");
                    done = true;
                } else {
                    // Wait for reply from server,
                    cipherDec.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec((byte[]) objectInput.readObject())); // To decrypt incoming messages from server, also receive IV vector
                    encryptedBytes = (byte[]) objectInput.readObject();  // Receive message from server
                    String str = new String(cipherDec.doFinal(encryptedBytes)); // Decrypt message from server
                    System.out.println(str); // Print message to console
                }
            }
        } catch (IllegalBlockSizeException | BadPaddingException
                | IOException | ClassNotFoundException e) {
            System.out.println("error in encrypted communication with server");
        } catch (InvalidAlgorithmParameterException | InvalidKeyException e) {
            e.printStackTrace();
        }
    }
}