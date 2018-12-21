/**
 * @author Lewis Linaker
 *
 * Method which maps the cipher text to its corrosponding plaintext
 * character
 */

import java.util.HashMap;

public class CipherText {

    private final String textToAnalyze;

    /**
     * @param fileText
     *
     * Method to get the CipherText file and convert it to a string
     */
    public CipherText(String fileText) {

        textToAnalyze = fileText;
     }

    /**
     * @param enInput
     * @param deInput
     * @return map
     *
     * Method used to match the cipher text letter to its corresponding plaintext letter
     */
    public HashMap matchLetters(String enInput,String deInput) {

        HashMap<String, String> map = new HashMap<>();
        String encryptedLetter = "";
        String decryptedLetter = "";
        String stringCh;

        // Loops through the alphabet and replaces the cipher text letter with the decrypted letter
        for (char ch = 'A'; ch <= 'Z'; ++ch) {
            stringCh = String.valueOf(ch);
            for(int i = 0; i < enInput.length(); i++) {
                if(String.valueOf(enInput.charAt(i)).equalsIgnoreCase(stringCh)) {
                    encryptedLetter = String.valueOf(enInput.charAt(i));
                    decryptedLetter = String.valueOf(deInput.charAt(i));
                    System.out.println(encryptedLetter + "> " + decryptedLetter);
                }
            }
            map.put(stringCh,(encryptedLetter.equalsIgnoreCase(stringCh) ? decryptedLetter : null ));
        }
        return map;
    }

    /**
     * @param word
     * @param map
     * @return stringToReturn
     *
     * Method used to replace the text
     */
    public String textReplacement(String word, HashMap<String, String> map) {

        String tmp = word;
        String stringToReturn = "";

        for(int i = 0; i < tmp.length(); i++) {

            if(!(String.valueOf(map.get(String.valueOf(tmp.charAt(i)).toUpperCase())).equals("null")))
                stringToReturn += String.valueOf(map.get(String.valueOf(tmp.charAt(i)).toUpperCase()));

            else
                stringToReturn += String.valueOf(tmp.charAt(i));
        }

        return stringToReturn;
    }
}
