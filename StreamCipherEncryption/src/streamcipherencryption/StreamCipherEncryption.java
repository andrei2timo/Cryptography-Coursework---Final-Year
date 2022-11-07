/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Main.java to edit this template
 */
package streamcipherencryption;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Random;
import java.util.Scanner;
import java.io.*;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;


/**
 *
 * @author suvit
 */
public class StreamCipherEncryption {
    public static void linearCongruentialMethod(int Xo, int p , int a, int b, int[] randomNums, int noOfRandomNums)
    {
        //Initialize the seed state
        randomNums[0] = Xo;
        // Traverse to generate required
        // numbers of random numbers
        for(int i=1;i<noOfRandomNums;i++)
            //Follow the linear congruential method
            randomNums[i] = ((randomNums[i - 1] * a) + b) % p;
    }
    public static long StreamCipher(String Message, String Key)
    {   
        /*
        int[] output = new int[Message.length()];
        String result = "";
        for(int i = 0; i < Message.length(); i++) 
        {   
            int d1= Integer.valueOf(Message.charAt(i));
            int d2= Integer.valueOf(Key.charAt(i));
            //System.out.println(d1 + " " + d2);
            int o = d1 ^ d2;
            output[i] = o;
        }
        result = Arrays.toString(output);
        return output;
        */
        long a = Long.parseLong(Message, 16);
        long b = Long.parseLong(Key,16);
        return a ^ b;
    }
    
    private static String convertStringToHex(String str) 
    {
        StringBuilder stringBuilder = new StringBuilder();

        char[] charArray = str.toCharArray();

        for (char c : charArray) 
        {
            String charToHex = Integer.toHexString(c);
            stringBuilder.append(charToHex);
        }
        return stringBuilder.toString();
    }
    public static String HexToBinary(long num)
    {
        String binary = Long.toBinaryString(num);
        return binary;
    }
    public static String convertHexToString(String str)
    {
       StringBuilder stringBuilder = new StringBuilder("");
       for(int i=0;i<str.length();i=i+2)
       {
           String s = str.substring(i,i+2);
           stringBuilder.append((char) Integer.parseInt(s,16));
       }
        return stringBuilder.toString();
    }
    public static String Hide_Message(String Original_Message, String Encrypted_Message)
    {   
        //add fullstop at the end of original message
        Original_Message += ".";
        Random rand = new Random(); //instance of random class
        //Convert secret message to form of "*" + white space
        for(int i=0;i<Encrypted_Message.length();i++)
        {   
            int int_random = rand.nextInt(Original_Message.length());
            // white space indicate "0"
            if(Encrypted_Message.charAt(i) == '0')
                Original_Message = Original_Message.substring(0,int_random) + '*' + Original_Message.substring(int_random);  
            else if(Encrypted_Message.charAt(i) == '1')
                Original_Message = Original_Message.substring(0,int_random) + ',' + Original_Message.substring(int_random); 
        }      
        return Original_Message;
    }
    public static String Decrypt(String Encrypted_Message)
    {   
        //add fullstop at the end of original message
        String binary="";
        //Convert secret message to form of "*" + white space
        for(int i=0;i<Encrypted_Message.length();i++)
        {   
            // white space indicate "0"
            if(Encrypted_Message.charAt(i) == '*')
                binary+="0";  
            else if(Encrypted_Message.charAt(i) == ',')
                binary+="1";  
        }      
        return binary;
    }
    public static void main(String[] args) throws IOException 
    {   
        String Key = "a73e80e2b563";
        String message1,message2;
        //readMessage_from_file(message1);
        
        Path fileName = Path.of("C:\\Users\\suvit\\Desktop\\StreamCipherEncryption\\src\\streamcipherencryption\\data.txt");
        // Now calling Files.readString() method to
        // read the file
        message1 = Files.readString(fileName);
        // Printing the string
        System.out.println(message1);
        
        //Read message 2 from the keyboard
        Scanner sc= new Scanner(System.in); //System.in is a standard input stream  
        System.out.print("message2:");  
        message2= sc.nextLine();//reads string
        
        //Convert the message into hex
        message2 = convertStringToHex(message2);
        //Display the converted message into hex and key onto screen
        System.out.println("The message in Hex is:" + message2);
        System.out.println("The key is: " + Key);
        
        //Encrypt the message using the key
        long result = StreamCipher(message2,Key);
        System.out.print("The encrypted message is: ");
        System.out.println(Long.toHexString(result));
        
        //The encrypted text displayed and generating the cipher-text
        System.out.println(result + " in binary is " + HexToBinary(result));
        System.out.println("The ciphertext generated is: ");
        System.out.println(Hide_Message(message1,HexToBinary(result)));
        
        
        
        
        System.out.println(Decrypt(Hide_Message(message1,HexToBinary(result))));
        long decryption_message2 = StreamCipher(Long.toHexString(result),Key);
        System.out.println(decryption_message2);
        String ForDecryption = Long.toHexString(decryption_message2);
        System.out.println(convertHexToString(ForDecryption));
    }
}
