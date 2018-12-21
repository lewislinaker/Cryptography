/**
 * @author: Lewis Linaker
 *
 * Cracker Class which is used to take in cipher text and its corresponding
 * plaintext, to create a key which is then used to crack another file which
 * has been encrypted with a substitution cipher.
 */

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Scanner;
import java.io.BufferedWriter;
import java.io.FileWriter;

public class Cracker {

    /**
     * @param args
     * @throws IOException
     *
     * Main method which calls various methods in order to crack a substitution
     * cipher. Takes in c1, p1, c2, output as command line arguments
     */
    public static void main(String[] args) throws IOException {

        String c1, c2, p1, output;

        c2 = args[2];
        String fileData = getFileTextAsString(c2);
        CipherText cipher = new CipherText(fileData);

        String encryptedText, decryptedText;
        c1 = args[0];
        encryptedText = getFileTextAsString(c1);

        p1 = args[1];
        decryptedText = getFileTextAsString(p1);

        output = args[3];

        HashMap<String,String> alphabetTable = cipher.matchLetters(encryptedText, decryptedText);
        Scanner stdIn = new Scanner(fileData);
        String tmp;

        // Used to write the deciphered text to a file.
        BufferedWriter writer = new BufferedWriter(new FileWriter(output));
        while(stdIn.hasNext()) {
            tmp = stdIn.next();
            writer.write(cipher.textReplacement(tmp, alphabetTable));
            writer.flush();
        }
    }

    /**
     * @param realFilePath
     * @return fileText
     * @throws IOException
     *
     * Method which is used to get the text from a file and converts it into
     * a string.
     */
    public static String getFileTextAsString(String realFilePath) throws IOException{
        File file = new File(realFilePath);
        FileInputStream fis = new FileInputStream(file);
        byte[] data = new byte[(int) file.length()];
        fis.read(data);//read data in file
        fis.close();//close file
        String fileText = new String(data, "UTF-8");
        return fileText;
    }

}
