/**
 * Author: Lewis Linaker
 *
 * Description: Client class which is used to communicate with a server
 * and perform a Diffle-Hellman Key Exchange
 */

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.net.*;
import java.io.*;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

public class Client {

    private MessageDigest digest;

    /**
     * @param args
     * @throws Exception
     *
     * Main Class which calls an instance of the Client class and the
     * setUpClient method.
     */
    public static void main(String[] args) throws Exception {

        new Client().setUpClient(args[0], args[1], args[2], args[3], args[4]);
    }

    /**
     * @param ip
     * @param port
     * @param inputP
     * @param inputG
     * @param inputA
     * @throws Exception
     *
     * SetUpClient class which is used to setup the client communication with the server.
     */
    private void setUpClient(String ip, String port, String inputP, String inputG, String inputA) throws Exception {

        // Big Integer values used for the key exchange
        BigInteger p = new BigInteger(inputP);
        BigInteger g = new BigInteger(inputG);
        BigInteger a = new BigInteger(inputA);

        // IP address and socket used to communicate with the server
        InetAddress address = InetAddress.getByName(ip);
        Socket socket = new Socket(address, Integer.valueOf(port));

        try {
            System.out.println("socket = " + socket);

            // Used to to read in and write to the server
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(socket.getOutputStream())), true);

            // Different method calls required to communicate with the server
            String nonce = createNonce();
            BigInteger key = createDHkey(g, a, p, out, in);
            String iv = createIv(key, nonce);
            byte[] sessionKey = createSessionKey(iv);

            // Outputs the Nonce
            out.println("**NONCE**" + nonce + "****");
            out.flush();

            // Request an encrypted file from the server
            String file = requestEncryptedFile(out, in, iv, sessionKey);

            // Outputs the decrypted file
            System.out.println("Decrypted Output: " + file);

            // Tries to verify a message from the server
            if (verifyMessage(file, out, in, iv, sessionKey)) {
                System.out.println("Verified successfully.");
            } else {
                System.out.println("Unsuccessful verification");
            }
            out.println("END");
        } catch (SocketException e) {
            System.out.println("Server closed connection");
        } finally {
            System.out.println("closing...");
            socket.close();
        }
    }

    /**
     * @param g
     * @param a
     * @param p
     * @param out
     * @param in
     * @return B.pow(a.intValue()).mod(p))
     * @throws Exception
     *
     * Method used to create DH key
     */
    private BigInteger createDHkey(BigInteger g, BigInteger a, BigInteger p, PrintWriter out, BufferedReader in) throws Exception {

        String A = "**DHA**" + (g.pow(a.intValue()).mod(p)).toString() + "****";
        out.println(A);
        String str = in.readLine();
        BigInteger B = BigInteger.valueOf(Long.valueOf(str.replaceAll("[^\\d]", "")));

        return (B.pow(a.intValue()).mod(p));
    }

    /**
     * @return String.valueOf(R)
     *
     * Method used to create Nonce (a random 4 digit number)
     */
    private String createNonce() {

        int R = (int) (Math.random() * 9000) + 1000;

        return String.valueOf(R);
    }

    /**
     * @param dhKey
     * @param R
     * @return R + paddedKey
     * @throws Exception
     *
     * Method used to create IV using R + paddedKey
     */
    private String createIv(BigInteger dhKey, String R) throws Exception {

        String paddedKey = String.format("%012d", dhKey.intValue());

        return R + paddedKey;
    }

    /**
     * @param concatenatedKey
     * @return new byte
     *
     *  Method used to create a session key using md5 hashing
     */
    private byte[] createSessionKey(String concatenatedKey) {

        try {
            digest = MessageDigest.getInstance("md5");
            byte[] hashed = digest.digest(concatenatedKey.getBytes());

            return Arrays.copyOf(hashed, 16);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return new byte[0];
    }

    /**
     * @param out
     * @param in
     * @param iv
     * @param sessionKey
     * @return parseMessage
     * @throws Exception
     *
     * Main method used to request an encrypted file from the server.
     */
    private String requestEncryptedFile(PrintWriter out, BufferedReader in, String iv, byte[] sessionKey) throws Exception {

        out.println("**REQ****"); // sends a request to the server

        String response = in.readLine(); // reads in a response
        String fileContents = response.substring(response.indexOf("****", 16));
        byte[] data = decryptFile(fileContents, iv, sessionKey);

        return parseMessage(new String(data));
    }

    /**
     * @param encryptedFile
     * @param iv
     * @param sessionKey
     * @return decoded
     * @throws Exception
     *
     *  Method used to decrypt a file
     */
    private byte[] decryptFile(String encryptedFile, String iv, byte[] sessionKey) throws Exception {

        IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes());
        SecretKeySpec skeySpec = new SecretKeySpec(sessionKey, "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivSpec);
        byte[] decoded = cipher.doFinal(Base64.getDecoder().decode(encryptedFile));

        return decoded;
    }

    /**
     *
     * @param hash
     * @param iv
     * @param sessionKey
     * @return encryptedFile
     * @throws Exception
     *
     * Method used to encrypt a file
     */
    private String encryptFile(byte[] hash, String iv, byte[] sessionKey) throws Exception {

        IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes());
        SecretKeySpec skeySpec = new SecretKeySpec(sessionKey, "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivSpec);
        byte[] encrypted = cipher.doFinal(hash);
        String encryptedFile = new String(Base64.getEncoder().encodeToString(encrypted).getBytes());

        return encryptedFile;
    }

    /**
     *
     * @param message
     * @param out
     * @param in
     * @param iv
     * @param sessionKey
     * @return VERIFIED
     * @throws Exception
     *
     *  Method used to verify a message from the server
     */
    private boolean verifyMessage(String message, PrintWriter out, BufferedReader in, String iv, byte[] sessionKey) throws Exception {

        byte[] hashedMessage = digest.digest(message.getBytes());
        String encryptedMessage = encryptFile(hashedMessage, iv, sessionKey);
        out.println("**VERIFY**" + encryptedMessage + "****");
        String response = in.readLine();
        out.flush();
        System.out.println("Server response: " + response);
        return (response.equals("**VERIFIED****"));
    }

    // Method used to parse a message
    private String parseMessage(String message) {

        return message.replaceFirst("DECRYPTED:", "");
    }

}