/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cryptography.practicle.pkg2;

import static java.lang.Math.abs;

/**
 *
 * @author Andrei Timo
 * Student ID:19000915
 */
public class MainForm extends javax.swing.JFrame {

    /**
     * Creates new form MainForm
     */
    public MainForm() {
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

        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        jTextField1 = new javax.swing.JTextField();
        jButton1 = new javax.swing.JButton();
        jButton2 = new javax.swing.JButton();
        jTextField2 = new javax.swing.JTextField();
        jTextField3 = new javax.swing.JTextField();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        jLabel1.setFont(new java.awt.Font("Tahoma", 0, 24)); // NOI18N
        jLabel1.setText("Error Checking Code Generator");

        jLabel2.setText("Enter Number for processing here:");

        jButton1.setText("BCH Generator");
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton1ActionPerformed(evt);
            }
        });

        jButton2.setText("BCH Decoder");
        jButton2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton2ActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(23, 23, 23)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(jButton1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jLabel2)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jTextField1))
                    .addComponent(jLabel1, javax.swing.GroupLayout.DEFAULT_SIZE, 350, Short.MAX_VALUE)
                    .addComponent(jButton2, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jTextField2)
                    .addComponent(jTextField3))
                .addContainerGap(23, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 36, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel2)
                    .addComponent(jTextField1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addComponent(jButton1, javax.swing.GroupLayout.PREFERRED_SIZE, 35, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(jTextField2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jButton2, javax.swing.GroupLayout.PREFERRED_SIZE, 35, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jTextField3, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(31, 31, 31))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    int arithmeticSqrRoot(int n)
    {
        switch(n)
        {
            case 1:
                return 1;
            case 2:
                return 0;
            case 3:
                return 5;
            case 4:
                return 2;
            case 5:
                return 4;
            case 6:
            case 7:
            case 8:
                return 0;
            case 9:
                return 3;
            case 10:
                return 0;   
        }
        return 0;   
    }
    
    //Special modulus function to only return positive values.
    private int signedMod(int num, int mod)
    {
        while(num < 0)
            num += 11;

        return num % mod;
    }
    
    //Special function to modulus values 
    private int modularInverse(int a, int b, int c)
    {
        for(int i = 0; i != c; ++i)
        {
            if(signedMod(b*i,c) == 1)
                return signedMod(a*i,c);
        }
        return 0;
    }
    
    private int[] StringToIntArray(String s, int size)
    {
        int[] intArray = new int[size];
        int counter = 0;
        for(int i = 0; i != s.length(); ++i)
        {  
            if(s.charAt(i) >= '0' && s.charAt(i) <= '9')
            {
                intArray[counter] = Integer.parseInt(String.valueOf(s.charAt(i)));
                ++counter;
            }
            if(s.charAt(i) == 'X')
                intArray[counter] = 10;
        }
        return intArray;
    }
    
    private int[] BCHGenerator(int[] d)
    {
        int[] ret = new int[10];
        
        ret[0] = d[0];
        ret[1] = d[1];
        ret[2] = d[2];
        ret[3] = d[3];
        ret[4] = d[4];
        ret[5] = d[5];
        ret[6] = signedMod((4*d[0]+10*d[1]+9*d[2]+2*d[3]+d[4]+7*d[5]), 11);
        ret[7] = signedMod((7*d[0]+8*d[1]+7*d[2]+d[3]+9*d[4]+6*d[5]), 11);
        ret[8] = signedMod((9*d[0]+d[1]+7*d[2]+8*d[3]+7*d[4]+7*d[5]), 11);
        ret[9] = signedMod((d[0]+2*d[1]+9*d[2]+10*d[3]+4*d[4]+d[5]), 11);
     
        return ret;
    }
    
    private int[] BCHSyndromeGenerator(int[] d)
    {
        int[] BCHSyndrome = new int[4];
        
        BCHSyndrome[0] = signedMod((d[0] + d[1] + d[2] + d[3] + d[4] + d[5] + d[6] + d[7] + d[8] + d[9]), 11);
        BCHSyndrome[1] = signedMod((d[0] + 2*d[1] + 3*d[2] + 4*d[3] + 5*d[4] + 6*d[5] + 7*d[6] + 8*d[7] + 9*d[8] + 10*d[9]), 11);
        BCHSyndrome[2] = signedMod((d[0] + 4*d[1] + 9*d[2] + 5*d[3] + 3*d[4] + 3*d[5] + 5*d[6] + 9*d[7] + 4*d[8] + d[9]), 11);
        BCHSyndrome[3] = signedMod((d[0] + 8*d[1] + 5*d[2] + 9*d[3] + 4*d[4] + 7*d[5] + 2*d[6] + 6*d[7] + 3*d[8] + 10*d[9]), 11);
        System.out.println("S1,S2,S3,S4 = " + BCHSyndrome[0] + " " + BCHSyndrome[1] + " " + BCHSyndrome[2] + " " + BCHSyndrome[3]);
        return BCHSyndrome;
    }
    
    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton1ActionPerformed
        int[] inputNumber = new int[6];
        int[] BCHCode = new int[10];
        
        String digitNumberString;
        digitNumberString = jTextField1.getText();
       
        inputNumber = StringToIntArray(digitNumberString, 6);
        
        BCHCode = BCHGenerator(inputNumber);
        
        if(digitNumberString.length() != 6)
            jTextField2.setText("Please enter number with 6 digits for error checking codes");
        else if(BCHCode[6] > 9 || BCHCode[7] > 9 || BCHCode[8] > 9 || BCHCode[9] > 9)
            jTextField2.setText("Unusable Number");
        else
        {
            digitNumberString = "";
            for(int i = 0; i != BCHCode.length; ++i)
            {
                digitNumberString += BCHCode[i];
            }
            jTextField2.setText(digitNumberString);
        }
    }//GEN-LAST:event_jButton1ActionPerformed

    private void jButton2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton2ActionPerformed
        int[] inputNumber = new int[10];
        int[] syndrome = new int[4];
        
        String digitNumberString;
        digitNumberString = jTextField2.getText();
       
        inputNumber = StringToIntArray(digitNumberString, 10);
        
        System.out.println("INPUT:" + digitNumberString);
        syndrome = BCHSyndromeGenerator(inputNumber);
        
        int p, q, r;
        
        p = signedMod((syndrome[1] * syndrome[1]) - (syndrome[0] * syndrome[2]), 11);
        q = signedMod((syndrome[0] * syndrome[3]) - (syndrome[1] * syndrome[2]), 11);
        r = signedMod((syndrome[2] * syndrome[2]) - (syndrome[1] * syndrome[3]), 11);
        System.out.println("p = " + p + "  q = " + q + "  r = " + r);
        if(digitNumberString.length() != 10)
            jTextField3.setText("Please enter number with 10 digits for syndrome numbers");
        else if(syndrome[0] == 0 && syndrome[1] == 0 && syndrome[2] == 0 && syndrome[3] == 0)
        {
            jTextField3.setText("No error");
        }
        else if(p == 0 && q == 0 && r == 0)
        {
            System.out.println(("" + syndrome[1] / syndrome[0]));
            int errorMagnitude = syndrome[0];
            int errorPosition = (modularInverse(syndrome[1], syndrome[0], 11))-1;
            if(errorPosition != -1)
            {
                inputNumber[errorPosition] = signedMod(inputNumber[errorPosition] - errorMagnitude, 11);

                digitNumberString = "";
                for(int i = 0; i != inputNumber.length; ++i)
                {
                    digitNumberString += inputNumber[i];
                }
                jTextField3.setText("One error present. Corrected code: " + digitNumberString);
            }
            else
                jTextField3.setText("More than two errors have occoured. ??");
        }
        else
        {
            double quad = (int) arithmeticSqrRoot(signedMod((int)Math.pow(q, 2) - 4 * p * r, 11));
            int ii = modularInverse((int) (-q + quad), 2 * p, 11);
            int j = modularInverse((int) (-q - quad), 2 * p, 11);
            
            int b = modularInverse((ii * syndrome[0] - syndrome[1]), (ii - j), 11);
            int a = syndrome[0] - b;
            
            if(ii == 0 || j == 0 || quad == 0)
            {
                jTextField3.setText("More than two errors have occoured. NO square root"); 
                System.out.println("There's no square root.");
            }
            else
            {
                inputNumber[ii-1] = signedMod(inputNumber[ii-1] - a, 11);
                inputNumber[j-1] = signedMod(inputNumber[j-1] - b, 11);

                digitNumberString = "";
                int ok = 1;
                for(int i = 0; i < inputNumber.length-1; ++i)
                {       
                        if(inputNumber[i]!=10)
                        {
                            ok=0;
                            break;
                        }
                        else
                        {
                            digitNumberString += inputNumber[i];
                            System.out.println("Digit:" + i + " " +inputNumber[i]);
                        }
                }
                if(ok==1)
                    jTextField3.setText("Two errors present. Corrected Code: " + digitNumberString);
                else
                    jTextField3.setText("More than two errors have occoured. ??");
            }
        }
    }//GEN-LAST:event_jButton2ActionPerformed

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
            java.util.logging.Logger.getLogger(MainForm.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(MainForm.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(MainForm.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(MainForm.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new MainForm().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton jButton1;
    private javax.swing.JButton jButton2;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JTextField jTextField1;
    private javax.swing.JTextField jTextField2;
    private javax.swing.JTextField jTextField3;
    // End of variables declaration//GEN-END:variables
}