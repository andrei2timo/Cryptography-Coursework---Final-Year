/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Build_RainbowTable;

import java.beans.XMLDecoder;
import java.beans.XMLEncoder;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import org.apache.commons.lang3.RandomStringUtils;

/**
 *
 * @author Andrei Timo
 */
public class Build_RainbowTable {
    String alphabet = "abcdefghijklmnopqrstuvwxyz";
    int chainLen = 5000;    // Length of chain
    int numChains = 2000;   // Number of chains
    int passSize = 6;       // Length of passwords
        
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws NoSuchAlgorithmException, UnsupportedEncodingException, IOException {
        Build_RainbowTable main = new Build_RainbowTable();
        
        HashMap table = new HashMap<String, String>();
        table = main.read_table();    // Get the so-far generated hashmap
        
        main.build_table(table);    // Continue building the table
        
        main.record_table(table);   // Record progress of hashmap
        //System.out.println(table);
    }
    
    public HashMap read_table() throws FileNotFoundException{
        FileInputStream file = new FileInputStream("C:\\Users\\suvit\\Desktop\\3rd Year\\Cryptography\\Java-Projects-main\\HashMap.xml");
        XMLDecoder d = new XMLDecoder(file);
        
        HashMap table = (HashMap) d.readObject();   // Read hashmap from xml file
        d.close();
        
        return table;
    }
    
    public void record_table(HashMap table) throws FileNotFoundException, IOException{
        FileOutputStream file = new FileOutputStream("C:\\Users\\suvit\\Desktop\\3rd Year\\Cryptography\\Java-Projects-main\\HashMap.xml");
        XMLEncoder e = new XMLEncoder(file);
        e.writeObject(table);    // Record hashmap to xml file
        e.flush();
        e.close();
    }
    
    public void build_table(HashMap table) throws NoSuchAlgorithmException, UnsupportedEncodingException{
        Build_RainbowTable main = new Build_RainbowTable();
        
        for(int i = 0; i < numChains; i++){    // For each chain:
            String start = main.randomString(6);    // Generate random password to start the chain with (length of 6 chars)
            
            String end = main.build_chain(start);   // Build the chain and get the last password
            if(table.containsKey(end)){        // Check if the chain is already recorded in the chain (kay is the last password in the chain)
                continue;
            }
            else{
                table.put(end, start);    // If it's not in table, place it there (key = last password; value = first)
            }
        }
    }
    
    public String build_chain(String beginning) throws NoSuchAlgorithmException, UnsupportedEncodingException{
        Build_RainbowTable main = new Build_RainbowTable();
        String start = beginning, pass = "";
        int position = 0;
        
        pass = main.generate_chainElements(start, position);  // Generate hash and reduction FROM THE START (randomly generated string)
        
        for(int i = 1; i < chainLen; i++){
            pass = main.generate_chainElements(pass, position);  // Generate hash and reduction from last reduction (password)
            position += 1;
        }
        
        return pass;
    }
    
    public String generate_chainElements(String start, int position) throws NoSuchAlgorithmException, UnsupportedEncodingException{
        Build_RainbowTable main = new Build_RainbowTable();
        
        String hash = main.f_SHA1(start);    // Hash the plain text password
        String pass = main.reduce(hash, position);    // Get new plain text password
        
        return pass;
    }
   
    public String reduce(String hash, int pos){
        Build_RainbowTable main = new Build_RainbowTable();
        
        BigInteger bigInt = new BigInteger(hash, 16);    // Create a big integer from the hash
        BigInteger position = BigInteger.valueOf(pos);   // Convert the position variable to big integer for calculations
        
        BigInteger PwSpSize = main.password_space();    // Get the maximum password length
        BigInteger prime = main.getPrime(PwSpSize);      // Get the next prime (prime > max psw. space)
        
        bigInt = bigInt.add(position);             // Add the current position in the chain to the generated big int
        bigInt = bigInt.mod(prime);           // Map the big int 0 - max password space size
        
        int uniqueInt = bigInt.intValue();
        String pass = main.intToPassword(uniqueInt);    // Get plain text password
        
        return pass;
    }
    
    public String intToPassword(int num){
        String pass = "";
        char letter;
        int base = alphabet.length();  
        
        while(num >= 0){
         
            int next = num % base;    // Get the reminder of the unique int
            letter = alphabet.charAt(next);    ///Use the reminder as index to find the next letter
            
            num /= base;   
            num -= 1;
            pass += letter;   // Combine all letters
        }
        return pass;
    }
    
    public String randomString(int length){
        
        String random = RandomStringUtils.randomAlphabetic(length).toLowerCase();  // Generate random string of lowercase alphabet and predefined length
        return random;
    }
    
    public BigInteger password_space(){
        int len = alphabet.length(); 
        BigInteger base = BigInteger.valueOf(len);   // The value to be powered
        BigInteger sum = BigInteger.valueOf(0);   // The Password Space Size (for the next probable prime)
        
        while(passSize > 0){
            BigInteger to_power = BigInteger.valueOf(1);   // Initialize the variable to be powered to 1
            
            for(int i = 0; i < passSize; i++){    // 26 on the power of the password length (6, 5, 4..0)
                to_power = to_power.multiply(base);
            }
            sum = sum.add(to_power);     // 26^6 + 26^5 + 26^4...26^1
            passSize -= 1;
        }
        sum = sum.add(BigInteger.valueOf(1));    // + 26^0
        
        return sum;
    }
    
    public BigInteger getPrime(BigInteger PwSpSize){
        
        BigInteger nextPrime = PwSpSize.nextProbablePrime();    // Generate the next prime (prime > password space 
        
        return nextPrime;
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
