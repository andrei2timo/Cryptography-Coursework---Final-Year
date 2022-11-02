/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package BruteForce_letters_digits;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.apache.commons.lang3.RandomStringUtils;
import java.io.File;
import java.io.IOException;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 *
 * @author Andrei Timo
 * This program will crack any password of length up to 6 including numbers (0-9) and lowercase letters (a-z)
 * It will record the discovered passwords and the time it took to find them in a file.
 */
public class BruteForce_letters_digits {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws NoSuchAlgorithmException, UnsupportedEncodingException, IOException {
        BruteForce_letters_digits main = new BruteForce_letters_digits();
        
        String[] to_crack = {"c2543fff3bfa6f144c2f06a7de6cd10c0b650cae",  // this   // All targets  0.0939 minutes
                             "b47f363e2b430c0647f14deea3eced9b0ef300ce",  // is                     0.00113 min
                             "e74295bfc2ed0b52d40073e8ebad555100df1380",  // very                   0.0555 min
                             "0f7d0d088b6ea936fb25b477722d734706fe8b40",  // simple                 5.1912 min
                             "77cfc481d3e76b543daf39e7f9bf86be2e664959",  // fail7                  19.7574 min
                             "5cc48a1da13ad8cef1f5fad70ead8362aabc68a1",  // 5you5                  0.6886 min
                             "4bcc3a95bdd9a11b28883290b03086e82af90212",  // 3crack                 2.8758 min
                             "7302ba343c5ef19004df7489794a0adaee68d285",  // 1you1                  1.6916 min
                             "21e7133508c40bbdf2be8a7bdc35b7de0b618ae4",  // 00if00                 15.5418 min
                             "6ef80072f39071d4118a6e7890e209d4dd07e504",  // cannot                 23.8227 min
                             "02285af8f969dc5c7b12be72fbce858997afe80a",  // 4this4                 6.6713 min
                             "57864da96344366865dd7cade69467d811a7961b"}; // 6will                  1.4959 min     All together: 24min
        
        
        List<String> t = Arrays.asList(to_crack);  // Add hashes to a list for comparing generated strings
        ArrayList<String> target = new ArrayList<String>(t);  // Convert to arraylist for the ability to remove objects from the list
        
        long start_time = System.nanoTime();  // Start recording
        main.break_passwords(target, start_time);
    }     
        
    public void break_passwords(ArrayList target, long start_time) throws NoSuchAlgorithmException, UnsupportedEncodingException, IOException{
        BruteForce_letters_digits main = new BruteForce_letters_digits();
        
        int loop = 0;
        do{
            String generated = main.randomString(1, 7);   // Generate a random string of length 1-6 bits
            String hashed = main.f_SHA1(generated);      // Hash it
            
            if(target.contains(hashed)){  // Compare it to targets
                //System.out.println("Password cracked: " + generated);
                main.writeToFile("\nPassword found: " + generated + "  From hash: " + hashed);  // Record the password to a file
                long end = System.nanoTime();          
                long time = end-start_time;
                main.writeToFile("\nTime: " + time);  // Record how long it took
                target.remove(hashed);
                
                if(target.isEmpty()){  // When all targets are found, the program will terminate
                    break;
                }
            }
        }
        while(loop == 0);  // Endless loop; the variable never changes
    }
    
    public String randomString(int lengthMin, int lengthMax){  // Generate a random string (inclusive length, exclusive length)
        
        String random = RandomStringUtils.randomAlphanumeric(lengthMin, lengthMax).toLowerCase();
        
        return random;
    }
    
    public void writeToFile(String password) throws IOException{
        File file = new File("C:\\Users\\suvit\\Desktop\\3rd Year\\Cryptography\\Java-Projects-main\\file1.txt");  // Record the cracked passwords
        
        FileWriter fr = new FileWriter(file, true);
        fr.write(password);
        fr.close();
    }
    
    public String f_SHA1(String text) throws NoSuchAlgorithmException, UnsupportedEncodingException { 
	
        MessageDigest md; 
	md = MessageDigest.getInstance("SHA-1");    // SHA-1 Encryption function
        
	byte[] sha1hash = new byte[40];     
	md.update(text.getBytes("iso-8859-1"), 0, text.length()); 
	sha1hash = md.digest(); 
        
	return convertToHex(sha1hash); 
    } 
    
    private String convertToHex(byte[] data) {
        
	StringBuffer buf = new StringBuffer(); 
	for (int i = 0; i < data.length; i++) { 
	      int halfbyte = (data[i] >>> 4) & 0x0F; 
	       int two_halfs = 0; 
	        do { 
	            if ((0 <= halfbyte) && (halfbyte <= 9)) 
	                buf.append((char) ('0' + halfbyte)); 
		else 
		    buf.append((char) ('a' + (halfbyte - 10))); 
		    halfbyte = data[i] & 0x0F; 
	        } 
                while(two_halfs++ < 1); 
	} 
	return buf.toString(); 
    }
    
}
