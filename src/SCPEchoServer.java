import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.util.Random;
import java.util.Scanner;

@SuppressWarnings("InfiniteLoopStatement")
public class SCPEchoServer {

    // The MultiEchoServer was provided by Yoonsik Cheon at least 10 years ago.
    // It was modified several times by Luc Longpre over the years.
    // This version is augmented by encrypting messages using AES encryption.
    // Used for Computer Security, Spring 2018.

    public static void main(String[] args) {
        System.out.println("Secure Communication Protocol Server Started.");
        int sessionID = 0; // assign incremental session ids to each client connection
        try {
            ServerSocket s = new ServerSocket(8008);
            // The server runs until an error occurs
            // or is stopped externally
            while (true) {
                Socket incoming = s.accept();
                // start a connection with the client
                // in a new thread and wait for another
                // connection
                new ClientHandler(incoming, ++sessionID).start();
                // start() causes the thread to begin execution
                // the JVM calls the run() method of this thread
            }
        } catch (Exception e) {
            System.out.println("Error: " + e);
        }
        System.out.println("Secure Communication Protocol Server Stopped.");
    }

    private static class ClientHandler extends Thread {

        Socket incoming;
        int id;

        ClientHandler(Socket incoming, int id) {
            this.incoming = incoming;
            this.id = id;
        }

        public void run() {
            try {

                PublicKey[] clientPublicKeys; // Stores the client's public key after verifying the certificate
                Cipher cipherEnc, cipherDec; // To encrypt and decrypt messages to/from client

                // in and out for socket communication using strings
                BufferedReader in = new BufferedReader(new InputStreamReader(incoming.getInputStream()));
                PrintWriter out = new PrintWriter(new OutputStreamWriter(incoming.getOutputStream()));
                System.out.println(in.readLine() + " from Client " + id + ". Initiating Connection.");

                try {
                    // read and send certificate to client
                    File file = new File("serverCertificate.txt");
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

                // Verify the client's certificate and retrieve its public keys
                clientPublicKeys = VerifyCert.vCert(in);

                // We could use Base64 encoding and communicate with strings using in and out
                // However, we show here how to send and receive serializable java objects
                ObjectInputStream objectInput = new ObjectInputStream(incoming.getInputStream());
                ObjectOutputStream objectOutput = new ObjectOutputStream(incoming.getOutputStream());

                // generate random bytes for shared secret
                byte[] serverRandomBytes = new byte[8];
                // the next line would initialize the byte array to random values
                new Random().nextBytes(serverRandomBytes);

                try {
                    assert clientPublicKeys != null;
                    byte[] encryptedBytes = Encrypt.encrypt(clientPublicKeys[0], serverRandomBytes); // Encrypt the server's random bytes with the client's encryption public key
                    objectOutput.writeObject(encryptedBytes); // Send encrypted bytes to the client
                    MessageDigest digest = MessageDigest.getInstance("SHA-256");
                    byte[] hashedBytes = digest.digest(serverRandomBytes); // Hash the server's random bytes with SHA-256, to create the signature
                    PrivateKey serverPrivateKeySig = PemUtils.readPrivateKey("jacmServerPrivateKey2.pem"); // Server Signature Private Key
                    byte[] signature = Sign.sign(serverPrivateKeySig, hashedBytes); // Sign the hashed random bytes
                    objectOutput.writeObject(signature); // Send signature to the client
                } catch (IOException | NoSuchAlgorithmException e) {
                    e.printStackTrace();
                    System.out.println("error computing or sending the signature for random bytes");
                    return;
                }

                // receive encrypted random bytes from client
                byte[] encryptedBytes = (byte[]) objectInput.readObject();
                // receive signature of hash of random bytes from client
                byte[] signatureBytes = (byte[]) objectInput.readObject();

                PrivateKey serverPrivateKeyEnc = PemUtils.readPrivateKey("jacmServerPrivateKey1.pem"); // Server Encryption Private Key
                byte[] clientRandomBytes = Decrypt.decrypt(serverPrivateKeyEnc, encryptedBytes); // Decrypt byte array, encrypted by the client with the server's public key

                // will need to verify the signature and decrypt the random bytes
                MessageDigest digest = MessageDigest.getInstance("SHA-256"); // Compute the SHA-256 of the decrypted bytes, to verify the certificate's signature
                byte[] hash = digest.digest(clientRandomBytes);
                boolean serverCertificate = Verify.verify(clientPublicKeys[1], hash, signatureBytes); // Verify that the received data matches the client's signature
                if (serverCertificate) {
                    System.out.println("Successfully Verified Client " + id + " Identity!");
                } else {
                    System.out.println("Failed To Verify Client " + id + " Identity!");
                    return;
                }
                // initialize the shared secret with all zeroes
                // will need to generate from a combination of the server and
                // the client random bytes generated
                byte[] sharedSecret = new byte[16];
                System.arraycopy(serverRandomBytes, 0, sharedSecret, 0, 8);
                assert clientRandomBytes != null;
                System.arraycopy(clientRandomBytes, 0, sharedSecret, 8, 8);
                SecretKeySpec secretKey = new SecretKeySpec(sharedSecret, "AES");
                try {
                    // we will use AES encryption, CBC chaining and PCS5 block padding
                    cipherEnc = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    cipherDec = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    // generate an AES key derived from randomBytes array
                    cipherDec.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec((byte[]) objectInput.readObject()));
                } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
                    System.out.println("error setting up the AES encryption");
                    return;
                }

                // keep echoing the strings received until
                // receiving the string "BYE" which will break
                // out of the for loop and close the thread
                for (; ; ) {
                    // get the encrypted bytes from the client as an object
                    byte[] encryptedByte = (byte[]) objectInput.readObject();
                    // decrypt the bytes
                    String str = new String(cipherDec.doFinal(encryptedByte));
                    // reply to the client with an echo of the string
                    // this reply is not encrypted, you need to modify this
                    // by encrypting the reply
                    String userStr = "Echo: " + str;
                    cipherEnc.init(Cipher.ENCRYPT_MODE, secretKey);
                    objectOutput.writeObject(cipherEnc.getIV()); // Send IV to client
                    encryptedByte = cipherEnc.doFinal(userStr.getBytes()); // Encrypt message to client
                    objectOutput.writeObject(encryptedByte); // Send message to client
                    objectOutput.flush();
                    // print the message received from the client
                    System.out.println("Received from session " + id + ": " + str);
                    if (str.trim().equals("BYE")) {
                        break;
                    }
                }
                System.out.println("Session " + id + " ended.");
                incoming.close();
            } catch (Exception e) {
                System.out.println("Error: " + e);
                e.printStackTrace();
            }
        }
    }
}