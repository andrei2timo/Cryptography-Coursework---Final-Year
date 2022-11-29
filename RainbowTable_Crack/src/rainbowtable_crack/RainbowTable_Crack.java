/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package rainbowtable_crack;

import java.beans.XMLDecoder;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

/**
 *
 * @author Andrei Timo
 */
public class RainbowTable_Crack {
    String alphabet = "abcdefghijklmnopqrstuvwxyz";   
    int chainLen = 5000;
    int passSize = 6;
    
    /**
     * @param args the command line arguments
     * 
     */
    public static void main(String[] args) throws FileNotFoundException, NoSuchAlgorithmException, UnsupportedEncodingException, IOException {
        RainbowTable_Crack main = new RainbowTable_Crack();
        //ntytjn, demhle, neyhxg, lantkk, jpnla,      // Test small hashmap
        //nffdzx, ukvyjt, wxnkum, kkfdgl, fgxctp, 
        //gnuomh, tmpyxz, wsqjyi, odqbbp, lulhlp, 
        //brarlh, qsghen, hynyeh, hhqbgk, vmrtza]
        
        //String t = "aadcar";
        //String target = main.f_SHA1(t);
        /*String red = main.reduce(target, 8);  //itiqzv
        System.out.println(red);*/
        
        HashMap table = main.read_table();   // Read the table from xml file
        
        String[] to_crack = {"ad9966bd4b4a82e086b3f96fb4132cbf284efdb9",   //zzaapf
                             "dc551ddda247d9307a340a57ce2679f9fbf70b71",   //oidhje
                             "fbc8fae6b1390136c802d43f16890134bfe73df7",   //great
                             "cadf11f0ed2fbdba016fa2935a466fe424e30565",   //poemda
                             "d9fba47a4be2b9c68349ecef481fc90fb10cca73",   //wichen
                             "a2b7caddbc353bd7d7ace2067b8c4e34db2097a3",   //zzzzz
                             "4eb3078d5c65f923173b5dc0a2be5af361362a61",   //okrmrw
                             "907916580d665b4fe4323f316cb3acd2d814e6f4",   //uuuxxx
                             "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",   //hello
                             "37e7e58c067169fb08c97978fff80a00dc57fdfd"};  //cieoe
        
        List<String> target = Arrays.asList(to_crack); 
        
        for(int i = 0; i < target.size(); i++){  // Attempt to crack each of hashes
            String t = target.get(i);
            main.lookup(t, table);
        }
        
        
    }
    
    public HashMap read_table() throws FileNotFoundException{
        FileInputStream file = new FileInputStream("C:\\Users\\suvit\\Desktop\\3rd Year\\Cryptography\\Java-Projects-main\\HashMap.xml");
        XMLDecoder d = new XMLDecoder(file);
        
        HashMap table = (HashMap) d.readObject();   // Read hashmap from xml file
        d.close();
        
        return table;
    }
    
    public void lookup(String target, HashMap table) throws NoSuchAlgorithmException, UnsupportedEncodingException{
        RainbowTable_Crack main = new RainbowTable_Crack();
        boolean found = false;
        
        ArrayList keys = new ArrayList();
        table.forEach((k, v) -> keys.add(k));    // Gather all the keys in a list (the last password of each chain)
        
        for(int i = 0; i < keys.size(); i++){
            String hash = main.f_SHA1((String) keys.get(i));  // Hash each key to check if the target is a key hash 
            
            if(hash.equals(target)){
                System.out.println("Password found: " + keys.get(i) + " |=> From hash: " + hash);
                found = true;
                break;
            }
        }
        
        ArrayList values = new ArrayList();
        table.forEach((k,v) -> values.add(v));    // Gather all the values (first passwords in chain)
        
        for(int i = 0; i < values.size(); i++){
            String to_hash = (String) values.get(i);
            String hash = main.f_SHA1(to_hash);    // Hash each value to check if the target is a value hash
            
            if(target.contains(hash)){
                System.out.println("Password found: " + to_hash + " |=> from hash: " + hash);
                found = true;
                break;
            }
        }
        
        if(found == false){    // If the target is not hash of a key or a value
            String key = "";
            for(int pos = chainLen-1; pos >= 0; pos--){    
                key = main.chainReduce(target, pos);  // Generate possible keys
            
                if(table.containsKey(key)){    // If the key value is in table, the chain is found
                    
                    String value = (String) table.get(key);    // Get the first password in chain (value in hashmap)
                    main.buildChain(value, target);         // Rebuild the rable from the start (value string)
                    break;
                }
            }
        }
    }
    
    public void buildChain(String start, String target) throws NoSuchAlgorithmException, UnsupportedEncodingException{
        RainbowTable_Crack main = new RainbowTable_Crack();
        
        String pass = start;    // Begin with the start of the chain (the value in hashmap)
        
        for(int pos = 0; pos < chainLen; pos++){   // Rebuild the chain
            String hash = main.f_SHA1(pass);
                
            if(hash.equals(target)){    // When target hash is detected inside the chain, 
                System.out.println("Password found: " + pass + " |=> From hash: " + hash);  //the previous result of reduction function is the password searched for
                break;
            }
            pass = main.reduce(hash, pos);
        }
    }
    
    public String chainReduce(String hash, int position) throws NoSuchAlgorithmException, UnsupportedEncodingException{
        RainbowTable_Crack main = new RainbowTable_Crack();
        
        String pass = "";
        
        while(position != chainLen-1){
            pass = main.reduce(hash, position);
            position += 1;    // Go back from the given position to the end of the chain
            hash = main.f_SHA1(pass);
        }
        
        return pass;    // Pass is the password at the final position in the chain (possible key in hashmap)
    }
    
    public String reduce(String hash, int pos){
        RainbowTable_Crack main = new RainbowTable_Crack();
        
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
        
        BigInteger nextPrime = PwSpSize.nextProbablePrime();    // Generate the next prime (prime > password space) 
        
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
