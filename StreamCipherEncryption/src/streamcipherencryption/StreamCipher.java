/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/GUIForms/JFrame.java to edit this template
 */
package streamcipherencryption;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Random;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.logging.Level;
import java.util.logging.Logger;

import java.util.*;
import java.util.function.*;
import java.util.stream.*;
/**
 *
 * @author Andrei Timo
 * Student ID: 19000915
 */
public class StreamCipher extends javax.swing.JFrame {

    String Key = "";
    String message2;
    String message1="";
    boolean CheckLength = false;
    //To generate the key using PRG
    int seed,p1,p2;
    public StreamCipher() {
        initComponents();
    }
    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jLabel3 = new javax.swing.JLabel();
        jLabel1 = new javax.swing.JLabel();
        jTextField1 = new javax.swing.JTextField();
        jTextField2 = new javax.swing.JTextField();
        jButton1 = new javax.swing.JButton();
        jTextField3 = new javax.swing.JTextField();
        jLabel2 = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();
        jTextField4 = new javax.swing.JTextField();
        jLabel5 = new javax.swing.JLabel();
        jScrollPane2 = new javax.swing.JScrollPane();
        jTextPane1 = new javax.swing.JTextPane();
        jButton2 = new javax.swing.JButton();
        jButton3 = new javax.swing.JButton();
        jLabel6 = new javax.swing.JLabel();
        jScrollPane3 = new javax.swing.JScrollPane();
        jTextPane2 = new javax.swing.JTextPane();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        jLabel3.setText("Message2:");

        jLabel1.setText("Key:");

        jTextField1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jTextField1ActionPerformed(evt);
            }
        });

        jButton1.setText("Encrypt");
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton1ActionPerformed(evt);
            }
        });

        jLabel2.setText("The message in hex is:");

        jLabel4.setText("The message after encryption is:");

        jLabel5.setText("Original message with hidden message:");

        jScrollPane2.setViewportView(jTextPane1);

        jButton2.setText("Decrypt");
        jButton2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton2ActionPerformed(evt);
            }
        });

        jButton3.setText("Generate Key");
        jButton3.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton3ActionPerformed(evt);
            }
        });

        jLabel6.setText("Introduce message1 below:");

        jScrollPane3.setViewportView(jTextPane2);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(28, 28, 28)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jScrollPane3, javax.swing.GroupLayout.PREFERRED_SIZE, 573, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jLabel2)
                            .addComponent(jTextField4, javax.swing.GroupLayout.PREFERRED_SIZE, 546, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jLabel4, javax.swing.GroupLayout.PREFERRED_SIZE, 186, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jTextField3, javax.swing.GroupLayout.PREFERRED_SIZE, 546, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(0, 0, Short.MAX_VALUE))
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                                    .addGroup(layout.createSequentialGroup()
                                        .addComponent(jLabel3, javax.swing.GroupLayout.PREFERRED_SIZE, 63, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(jTextField1, javax.swing.GroupLayout.PREFERRED_SIZE, 265, javax.swing.GroupLayout.PREFERRED_SIZE))
                                    .addGroup(javax.swing.GroupLayout.Alignment.LEADING, layout.createSequentialGroup()
                                        .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 37, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(jTextField2)))
                                .addGap(30, 30, 30)
                                .addComponent(jButton3)
                                .addGap(56, 56, 56)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(jButton2)
                                    .addComponent(jButton1)))
                            .addComponent(jLabel5, javax.swing.GroupLayout.PREFERRED_SIZE, 222, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 573, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jLabel6))
                        .addContainerGap(17, Short.MAX_VALUE))))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(42, 42, 42)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jLabel3)
                            .addComponent(jTextField1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(6, 6, 6))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(jButton1)
                        .addGap(18, 18, 18)))
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel1)
                    .addComponent(jTextField2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jButton3)
                    .addComponent(jButton2))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel6)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane3, javax.swing.GroupLayout.PREFERRED_SIZE, 113, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(26, 26, 26)
                .addComponent(jLabel2, javax.swing.GroupLayout.PREFERRED_SIZE, 29, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jTextField4, javax.swing.GroupLayout.PREFERRED_SIZE, 32, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jLabel4)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jTextField3, javax.swing.GroupLayout.PREFERRED_SIZE, 32, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jLabel5)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 121, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents
    //---------------------------------------------------------------------------------------------------------------
    //Method GCD - calculates the great common divisor of 2 numbers
    //This method is used to generate a new seed which is co-prime with m=p1*p2
    public static int GCD(int n1, int n2) 
    {
        if(n2 == 0) 
            return n1;
        return GCD(n2, n1 % n2);
    }
    
    //---------------------------------------------------------------------------------------------------------------
    //Method getRandomInRange - generates a random number between start and end
    public static int getRandomInRange(int start, int end)
    {   
        Random generator = new Random();
        return start + generator.nextInt(end - start + 1); 
    }
    
    //---------------------------------------------------------------------------------------------------------------
    //Method findParity(long x) - it display the binary parity of a long number
    //e.g. parity(7)=parity(0x0111)=1
    //     parity(10)=parity(0x1010)=0
    //This method helps to convert the BBS values into parity binary and use them to generate the key
    public static int findParity(long x)
    {   
        short result=0;
        while (x!=0)
        {
            result ^=1;//Xor the result
            x &= (x-1);//AND logic for current bit and next one
        }
        return result;
    }
    
    //---------------------------------------------------------------------------------------------------------------
    //Method isPrime(int x) - check if a number is prime
    //This method is going to help in order to generate p1 and p2 which are primes
    private static int isPrime(int x)
    {
        if(x==2)
            return 1;
        if(x<2 || x%2==0)
            return 0;
        for(int i=3;i<=Math.sqrt(x);i++)
            if(x%i==0)
                return 0;
        return 1;
    }
    
    //---------------------------------------------------------------------------------------------------------------
    //Method generateRandomPrime() - generates a random prime number
    //This function checks if the number is prime. In affirmative case, it checks
    //if the prime_number mod 4 is 3. If yes, we store the value into an array.
    public static int generateRandomPrime()
    {
        int num=0;
        int first_prime=7,i=0,k=0;
        int[] primes = new int[30];
        //Generate the prime numbers from [7,500] which respects the conditions
        while(i<500 && k<30)
        {   
            //the number is prime and the number mod 4 is 3
            if(isPrime(first_prime)==1 && first_prime%4==3)
            {
                //System.out.println(first_prime);
                primes[k]=first_prime;//Store the number into the array
                k++;//Go through the array
            }
            if(k==30)//If we reached the limit of our array, we break from the loop
                break;
            first_prime++;//We increment the prime
            i++;//We go through the primes    
        } 
        //Generate a random position into the array
        int pos=getRandomInRange(0,29);
        //Asign the value from that random position to num
        num = primes[pos];
        return num;  // return the number
    }
    
    //---------------------------------------------------------------------------------------------------------------
    //Method blumblum_shub - generates a new key each time
    //Using the random generated seed,p1,p2. It stores in randomNums array the parity bits of the operation:
    //X[i+1] = (X[i]*X[i]) % m , where m = p1*p2
    public static String blumblum_shub(int Xo, long p1 , long p2, int[] randomNums, int noOfRandomNums)
    {
        //Initialize the key as a null string
        String Key="";
        long m=p1*p2;
        //Initialize the seed state
        randomNums[0] = Xo;
        // Traverse to generate required numbers of random numbers
        for(int i=0;i<noOfRandomNums-1;i++)
            randomNums[i+1]=(int) ((randomNums[i]*randomNums[i])%m);
        //Replace in the array the parity of the number from position i
        for(int i=0;i<noOfRandomNums;i++)
            randomNums[i] = findParity(randomNums[i]);
        //Append the parity number to the key
        for(int i=0;i<noOfRandomNums;i++)
            Key += randomNums[i];
        //Return the Key
        return Key; 
    }
    
    //---------------------------------------------------------------------------------------------------------------
    //Method XOR - helps to Encrypt/Decrypt the Data
    public static BigInteger XOR(String Message, String Key)
    {   
        BigInteger message2_converted = new BigInteger(Message, 16);
        BigInteger Key_converted = new BigInteger(Key, 16);
        BigInteger result = message2_converted.xor(Key_converted);
        return result;
    }
    
    //---------------------------------------------------------------------------------------------------------------
    //Method convertStringToHex - converts a string number to a Hexadecimal number
    private static String convertStringToHex(String str) 
    {   
        //create a new string to store the value, step-by-step
        StringBuilder stringBuilder = new StringBuilder();
        //Break the string into a char string to go through it a for-loop
        char[] charArray = str.toCharArray();
        for (char c : charArray) 
        {   
            //Convert the character to a hex number
            String charToHex = Integer.toHexString(c);
            //Append the character to a new string
            stringBuilder.append(charToHex);
        }
        return stringBuilder.toString();
    }
    
    //---------------------------------------------------------------------------------------------------------------
    //Method HexToBinary - converts a hex number into binary
    public static String HexToBinary(long num)
    {
        String binary = Long.toBinaryString(num);
        return binary;
    }
    
    //---------------------------------------------------------------------------------------------------------------
    //Method binaryToHex - converts a binary string to hex
    public static String binaryToHex(String str)
    {
       return new BigInteger(str, 2).toString(16);
    }
    
    //---------------------------------------------------------------------------------------------------------------
    //Method convertHexToString - converts a Hex number back to String (for Decryption)
    public static String convertHexToString(String str)
    {  
       //create a new string to store the value, step-by-step
       StringBuilder stringBuilder = new StringBuilder("");
       for(int i=0;i<str.length();i=i+2)//go through the string
       {
           String s = str.substring(i,i+2);//Take a substring of 2 characters from the string
           //Convert the substring to string and append it to the new string
           stringBuilder.append((char) Integer.parseInt(s,16));
       }
        return stringBuilder.toString();
    }
    
    //---------------------------------------------------------------------------------------------------------------
    //Method Hide_Message - this method represents the Steganography part of the assignment
    public static String Hide_Message(String Original_Message, String Encrypted_Message)
    {   
        //add fullstop at the end of original message
        for(int j=1;j<Original_Message.length();j++)
             if(Original_Message.charAt(j) == '.' && (Original_Message.charAt(j-1) >= 'a' && Original_Message.charAt(j-1) <= 'z'))
                  Original_Message = Original_Message.substring(0,j) + '.' + Original_Message.substring(j);
        
        //Convert secret message to form of single white spaces and double white spaces
        for(int j=0;j<Original_Message.length()-1;j++)
        {   
            for(int i=0;i<Encrypted_Message.length();i++)
            {   
                //check if at position j+1 we have a space and the previous and next positions (j and j+2) we have a character from 'a' - 'z' range
                if(Original_Message.charAt(j+1) == ' ' && (Original_Message.charAt(j) >= 'a' && Original_Message.charAt(j) <= 'z') &&
                  (Original_Message.charAt(j+2) >= 'A' && Original_Message.charAt(j+2) <= 'Z' || 
                   Original_Message.charAt(j+2) >= 'a' && Original_Message.charAt(j+2) <= 'z'))
                {
                    if(Encrypted_Message.charAt(i) == '0')//single white space for 0's
                        Original_Message = Original_Message.substring(0,j+1) + ' ' + Original_Message.substring(j+1);
                    if(Encrypted_Message.charAt(i) == '1')//double white spaces for 1's
                        Original_Message = Original_Message.substring(0,j+1) + ' ' + ' ' + Original_Message.substring(j+1); 
                }
            }
        }      
        return Original_Message;
    }
    
    //---------------------------------------------------------------------------------------------------------------
    //Method Decrypt - this method represents the Steganography part of the assignment
    //Remove the secret message from the message and store it 
    public static String Decrypt(String Encrypted_Message, String message1)
    {   
        //to build the binary set
        String binary="";
        //Decrypt the message by deleting the "." and "white spaces"
        for(int i=0;i<Encrypted_Message.length();i++)
        {   
            // "." indicate "0"
            if(Encrypted_Message.charAt(i) == '.')
            {
                //Delete '.' from position i
                Encrypted_Message = Encrypted_Message.substring(0,i) + Encrypted_Message.substring(i+1);
                binary += "0";
                //In case we have 2 "." together, we need to go back one position
                i--;
            }  
            if(Encrypted_Message.charAt(i) == ' ')
            {   
                //Delete ' ' from position i
                binary+="1";
                Encrypted_Message = Encrypted_Message.substring(0,i) + Encrypted_Message.substring(i+1);
                //In case we have 2 white spaces together, we need to go back one position
                i--;
            }
        }
        //Make a copy of the decrypted message to display it on the GUI
        message1=String.valueOf(Encrypted_Message);
        return binary;
    }
    
    //---------------------------------------------------------------------------------------------------------------
    //Method removeDuplicates - remove duplicates words from a String
    public static String removeDuplicates(String str)
    {   
        str = Arrays.stream(str.split(" ")).distinct().collect(Collectors.joining(" "));
        return str;
    }
    
    //---------------------------------------------------------------------------------------------------------------
    //Method toBinary - converts a hex string to binary
    public static String toBinary(String s) {
        return new BigInteger(s, 16).toString(2);
    }
    //---------------------------------------------------------------------------------------------------------------
    private void jTextField1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jTextField1ActionPerformed

    }//GEN-LAST:event_jTextField1ActionPerformed

    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton1ActionPerformed
        jLabel2.setText("The message in hex is:");
        jLabel4.setText("The message after encryption is:");
        jLabel5.setText("Original message with hidden message:");
        //get message1 string from the text pane
        message1 = jTextPane2.getText();
        
        //Check if the length of the string (from file) is less than 20 characters
        if(message1.length()<20)
        {    
            //Make a copy of the original message1
            String msg=String.valueOf(message1);
            CheckLength = true;
            //We duplicate the text 15 times
            for(int k=0;k<14;k++)
            {
                message1 += " ";
                message1 += msg;
            }
        }
        //Get the message2 from the TextField
        message2 = jTextField1.getText();
        
        //Convert the message2 from String to Hex
        message2 = convertStringToHex(message2);
        
        //Encrypt the message using the key
        BigInteger XOR_result = XOR(message2,Key);
        
        //Convert the bigInteger to String and assign the value to the text field
        String XOR_result_converted = XOR_result.toString(16); 
        jTextField3.setText(XOR_result_converted);
        
        //Display the converted message into hex on the console
        jTextField4.setText(message2);
        
        //The encrypted text displayed and generating the cipher-text
        jTextPane1.setText(Hide_Message(message1,toBinary(XOR_result_converted)));
        
    }//GEN-LAST:event_jButton1ActionPerformed

    private void jButton2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton2ActionPerformed
        jLabel2.setText("");
        jLabel2.setText("The Key is: ");

        jTextField4.setText("");
        jTextField4.setText(Key);
        
        //XOR between original message 2 and the key
        BigInteger result = XOR(message2,Key);
        //Convert the bigInteger to String and assign the value to the text field
        //Decrypt the hidden message - and get message2
        String XOR_result_converted = result.toString(16);
        BigInteger decryption_message2 = XOR(XOR_result_converted,Key);
        
        //Convert message2 (from BigInteger) to Hex
        String message2_decrypted = decryption_message2.toString(16); 

        jLabel4.setText("");
        jLabel4.setText("The decrypted message is: ");
        
        jTextField3.setText("");
        //Assign the converted value from hex to String to the text field
        jTextField3.setText(convertHexToString(message2_decrypted));
        
        //Clear the label when decryption button is clicked
        jLabel5.setText("");
        jLabel5.setText("Original message after decryption:");
        //Set the panel text to message1 after decryption
        if(CheckLength == false)
            jTextPane1.setText(message1);
        else 
            jTextPane1.setText(removeDuplicates(message1));
    }//GEN-LAST:event_jButton2ActionPerformed

    private void jButton3ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton3ActionPerformed
        //Method GUI to generate a key
        //Initialise p1 and p2 with a random prime number
        p1=generateRandomPrime();
        p2=generateRandomPrime();
        //Firstly, initialise the seed with a random number between 1 and 30
        seed=getRandomInRange(1,30);
        while(GCD(seed,p1*p2)!=1)//While the seed and p1*p2 are not co-prime
            seed=getRandomInRange(1,100);//generate a new seed      
        
        //Create and generate the array which stores the parity determined by Blum Blum Shub Generator
        int[] randomNums = new int[72];
        //Call the Blum Blum Shub method and store the result into variable 
        String variable = blumblum_shub(seed, p1,p2, randomNums, 72);
        
        //Convert the binary key to hex
        Key = binaryToHex(variable);

        //Set the text of the field to the found Key
        jTextField2.setText(Key);
    }//GEN-LAST:event_jButton3ActionPerformed

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(StreamCipher.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(StreamCipher.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(StreamCipher.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(StreamCipher.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new StreamCipher().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton jButton1;
    private javax.swing.JButton jButton2;
    private javax.swing.JButton jButton3;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane jScrollPane3;
    private javax.swing.JTextField jTextField1;
    private javax.swing.JTextField jTextField2;
    private javax.swing.JTextField jTextField3;
    private javax.swing.JTextField jTextField4;
    private javax.swing.JTextPane jTextPane1;
    private javax.swing.JTextPane jTextPane2;
    // End of variables declaration//GEN-END:variables
}
