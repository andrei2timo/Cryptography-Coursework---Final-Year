/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cryptography_project_4;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import org.apache.commons.lang3.RandomStringUtils;
import java.io.File;
import java.io.IOException;
import java.io.FileWriter;
import java.util.Arrays;
import java.util.List;

/**
 *
 * @author Andrei Timo
 */
public class BruteForce_BCH_codes {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
        BruteForce_BCH_codes main = new BruteForce_BCH_codes();
        //ArrayList target = new ArrayList();
                             
        String[] to_crack = {"902608824fae2a1918d54d569d20819a4288a4e4",     // 0000118435      0.1508 seconds
                             "88d0b34055b79644196fce25f876bc1a5ef654d3",     // 1111110565      1.6115 seconds
                             "5b8f495b7f02b62eb228c5dbece7c2f81b60b9a3"};    // 8888880747      2.90912 seconds   All together: 3 seconds
        
        
        List<String> t = Arrays.asList(to_crack);
        ArrayList<String> target = new ArrayList<String>(t);  // Convert to arraylist for the ability to remove objects from the list
        
        long start_time = System.nanoTime();   // Start recording time
        
        main.break_passwords(target, start_time); 
    }
    
    public void break_passwords(List<String> target, long start_time) throws NoSuchAlgorithmException, UnsupportedEncodingException, IOException{
        BruteForce_BCH_codes main = new BruteForce_BCH_codes();
        
        int loop = 0; 
        do{
            loop += 1;
            String generated = main.randomString(6);  // Generate a random 6-digit number
            String bch = main.encode(generated);      // Generate its parity bits (other 4 digits)
            
            if(bch != null){     // If the number is a usable BCH code
                String hashed = main.f_SHA1(bch);  // Hash it
                
                if(target.contains(hashed)){    // and compare it with the target
                    main.writeToFile("\n" + bch);  // Write password to file, if found
                    target.remove(hashed);
                    long end = System.nanoTime();          
                    long time = end-start_time;
                    main.writeToFile("\nTime: " + time);  // Record how long it took
                    
                    if(target.isEmpty()){  // Do this, until all targets are found
                        break;
                    }
                }
            }
            
        }
        while(loop < 1000000000);  // Endless loop
    }
    
    public String randomString(int length){
        
        String random = RandomStringUtils.randomNumeric(length);  // Random string of set number of digits
        
        return random;
    }
    
    public String encode(String generated){
        int[]d = new int[10];
        boolean usable = true;
        String bch = null;
        
        int length = generated.length();   // The generated 6 digit number
        for(int i = 0; i < length; i++){  
            d[i] = Integer.parseInt(String.valueOf(generated.charAt(i)));  // split into chars
        }
        d[6] = 4*d[0] + 10*d[1] + 9*d[2] + 2*d[3] + d[4] + 7*d[5];
        d[7] = 7*d[0] + 8*d[1] + 7*d[2] + d[3] + 9*d[4] + 6*d[5];
        d[8] = 9*d[0] + d[1] + 7*d[2] + 8*d[3] + 7*d[4] + 7*d[5];
        d[9] = d[0] + 2*d[1] + 9*d[2] + 10*d[3] + 4*d[4] + d[5];   // The other 4 digits
        
        for(int n = 6; n < 10; n++){
            d[n] %= 11;                 // Evaluate the 4 last digits (mod 11)
            if(d[n] >= 10){                    // If any equals 10, the number is unusable
                usable = false;
            }
        }
        
        if(usable = true){
            for(int i = 0; i < 10; i++){ // Place all 10 digits into a string, when the number is a usable BCH code
                bch += String.valueOf(d[i]);
            }
            bch = bch.replace("null", "");
        }
                
        return bch;
    }
    
    public void writeToFile(String password) throws IOException{
        File file = new File("C:\\Users\\suvit\\Desktop\\3rd Year\\Cryptography\\file.txt");
        
        FileWriter fr = new FileWriter(file, true);  // Used for recording passwords and cracking times to file
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
