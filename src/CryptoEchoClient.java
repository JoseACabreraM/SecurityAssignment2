//import javax.crypto.Cipher;
//import javax.crypto.spec.IvParameterSpec;
//import javax.crypto.spec.SecretKeySpec;
//import java.io.*;
//import java.net.Socket;
//import java.util.Scanner;
//
//public class CryptoEchoClient {
//    // The MultiEchoServer was provided by Yoonsik Cheon at least 10 years ago.
//    // It was modified several times by Luc Longpre over the years.
//    // This version is augmented by encrypting messages using AES encryption.
//    // Used for Computer Security, Spring 2018.
//    public static void main(String[] args) {
//
//        String host;
//        Scanner userInput = new Scanner(System.in);
//        if (args.length > 0) {
//            host = args[0];
//        } else {
//            System.out.println("Enter the server's address: (IP address or \"localhost\")");
//            host = userInput.nextLine();
//        }
//        try {
//            Socket socket = new Socket(host, 8008);
//
//            // in and out for socket communication using strings
//            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
//            System.out.println(in.readLine());
//            PrintWriter out = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));
//
//            // We could use Base64 encoding and communicate with strings using in and out
//            // However, we show here how to send and receive serializable java objects
//            ObjectOutputStream objectOutput = new ObjectOutputStream(socket.getOutputStream());
//            ObjectInputStream objectInput = new ObjectInputStream(socket.getInputStream());
//
//            // read the file of random bytes from which we can derive an AES key
//            byte[] randomBytes;
//            try {
//                FileInputStream fis = new FileInputStream("randomBytes");
//                randomBytes = new byte[fis.available()];
//            } catch (Exception e) {
//                System.out.println("problem reading the randomBytes file");
//                return;
//            }
//            // we will use AES encryption, CBC chaining and PCS5 block padding
//            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
//            // generate an AES key derived from randomBytes array
//            SecretKeySpec secretKey = new SecretKeySpec(randomBytes, "AES");
//            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
//            // the initialization vector was generated randomly
//            // transmit the initialization vector to the server
//            // no need to encrypt the initialization vector
//            // send the vector as an object
//            byte[] iv = cipher.getIV();
//            objectOutput.writeObject(iv);
//            Cipher cipher1 = Cipher.getInstance("AES/CBC/PKCS5Padding");
//            System.out.println("Starting messages to the server. Type messages, type BYE to end");
//            boolean done = false;
//            while (!done) {
//                // Read message from the user
//                String userStr = userInput.nextLine();
//                // Encrypt the message
//                byte[] encryptedByte = cipher.doFinal(userStr.getBytes("UTF-8"));
//                // Send encrypted message as an object to the server
//                objectOutput.writeObject(encryptedByte);
//                objectOutput.flush();
//                // If user says "BYE", end session
//                if (userStr.trim().equals("BYE")) {
//                    System.out.println("client session ended");
//                    done = true;
//                } else {
//                    // Receive the encrypted reply from the server, decrypt the reply and print it
//                    cipher1.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec((byte[]) objectInput.readObject()));
//                    encryptedByte = (byte[]) objectInput.readObject();
//                    String str = new String(cipher1.doFinal(encryptedByte));
//                    System.out.println(str);
//                }
//            }
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//    }
//}
