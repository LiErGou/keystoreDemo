package com.example.licl.keystoredemo.utils;

import android.content.Context;
import android.security.KeyPairGeneratorSpec;
import android.util.Log;
import android.widget.Toast;
import android.util.Base64;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.security.auth.x500.X500Principal;

//before use this util you should excute the "createNewKeys()" method.

public class KeyStoreUtil {

    private KeyStore mKeyStore;
    private static String TAG="KeyStoreUtil";
    private Context mContext=null;




    private String mAlias =null;

    public KeyStoreUtil(Context context){

        mContext=context;

        init();
    }

    private void init(){
        try{
            mKeyStore =KeyStore.getInstance("AndroidKeyStore");
            mKeyStore.load(null);
        }catch (Exception e){
            Log.e(TAG,"keyStroe load erro");
            e.printStackTrace();
        }
    }



    public void createNewKeys(){
        try{
            if(!mKeyStore.containsAlias(mAlias)){
                Calendar start = Calendar.getInstance();
                Calendar end=Calendar.getInstance();
                end.add(Calendar.YEAR,1);
                KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(mContext)
                        .setAlias(mAlias)
                        .setSubject(new X500Principal("CN=Sample Name, O=Android Authority"))
                        .setSerialNumber(BigInteger.ONE)
                        .setStartDate(start.getTime())
                        .setEndDate(end.getTime())
                        .build();
                KeyPairGenerator generator=KeyPairGenerator.getInstance("RSA","AndroidKeyStore");
                generator.initialize(spec);

                KeyPair keyPair=generator.generateKeyPair();
            }
        }catch (Exception e){
            Toast.makeText(mContext,"Exception " + e.getMessage() + " occured", Toast.LENGTH_LONG).show();
            Log.e(TAG, Log.getStackTraceString(e));
        }

    }

    public String encryptString(String initialText){
        try{
            if (mAlias==null||mAlias.isEmpty()){
                return "alias is null or empty";
            }
            if(!mKeyStore.containsAlias(mAlias)){
                return "keystore does not contain alias";
            }
            KeyStore.PrivateKeyEntry privateKeyEntry=(KeyStore.PrivateKeyEntry) mKeyStore.getEntry(mAlias,null);
            RSAPublicKey publicKey=(RSAPublicKey) privateKeyEntry.getCertificate().getPublicKey();

            Cipher inCipher=Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidOpenSSL");
            inCipher.init(Cipher.ENCRYPT_MODE,publicKey);

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            CipherOutputStream cipherOutputStream = new CipherOutputStream(
                    outputStream, inCipher);
            cipherOutputStream.write(initialText.getBytes("UTF-8"));
            cipherOutputStream.close();
            byte [] vals = outputStream.toByteArray();
            String finished=Base64.encodeToString(vals, Base64.DEFAULT);
            return finished;
        }catch (Exception e){
            e.printStackTrace();
            Log.e(TAG, Log.getStackTraceString(e));
            return "Encrypt Failed";
        }
    }

    public String decryptString(String cipherText){

        try{
            if (mAlias==null||mAlias.isEmpty()){
                return "alias is null or empty";
            }
            if(!mKeyStore.containsAlias(mAlias)){
                return "keystore does not contain alias";
            }
            KeyStore.PrivateKeyEntry privateKeyEntry=(KeyStore.PrivateKeyEntry) mKeyStore.getEntry(mAlias,null);

            Cipher output=Cipher.getInstance("RSA/ECB/PKCS1Padding");
            output.init(Cipher.DECRYPT_MODE,privateKeyEntry.getPrivateKey());

            CipherInputStream cipherInputStream=new CipherInputStream(new ByteArrayInputStream(Base64.decode(cipherText,
                    Base64.DEFAULT)), output);
            ArrayList<Byte> values=new ArrayList<>();
            int nextByte;
            while ((nextByte = cipherInputStream.read()) != -1) {
                values.add((byte)nextByte);
            }

            byte[] bytes = new byte[values.size()];
            for(int i = 0; i < bytes.length; i++) {
                bytes[i] = values.get(i).byteValue();
            }

            String finalText = new String(bytes, 0, bytes.length, "UTF-8");
            return finalText;
        }catch (Exception e){
            Toast.makeText(mContext,"Exception " + e.getMessage() + " occured", Toast.LENGTH_LONG).show();
            Log.e(TAG, Log.getStackTraceString(e));
            return "Decrypt Failed";
        }
    }

    public boolean encryptFile(String srcFile,
                              String destionFile){
        int len = 0;
        byte[] buffer = new byte[128];
        byte[] cipherbuffer = null;
        try{
            if (mAlias==null||mAlias.isEmpty()){
                return false;
            }
            if(!mKeyStore.containsAlias(mAlias)){
                return false;
            }
            KeyStore.PrivateKeyEntry privateKeyEntry=(KeyStore.PrivateKeyEntry
                    ) mKeyStore.getEntry(mAlias,null);
            RSAPublicKey publicKey=(RSAPublicKey)
                    privateKeyEntry.getCertificate().getPublicKey();

            Cipher inCipher=Cipher.getInstance("RSA/ECB/PKCS1Padding",
                    "AndroidOpenSSL");
            inCipher.init(Cipher.ENCRYPT_MODE,publicKey);

            FileInputStream fis = new FileInputStream(new File(srcFile));
            FileOutputStream fos = new FileOutputStream(new File(destionFile));

            // 读取原文，加密并写密文到输出文件。
            while ((len = fis.read(buffer)) != -1) {
                cipherbuffer = inCipher.update(buffer, 0, len);
                fos.write(cipherbuffer);
                fos.flush();
            }
            cipherbuffer = inCipher.doFinal();
            fos.write(cipherbuffer);
            fos.flush();

            if (fis != null)
                fis.close();
            if (fos != null)
                fos.close();


            return true;
        }catch (Exception e){
            e.printStackTrace();
            Log.e(TAG, Log.getStackTraceString(e));
            return false;
        }
    }

    public boolean decryptFile(String srcFile,
                              String destionFile){
        int len = 0;
        byte[] buffer = new byte[5 * 1024];
        byte[] plainbuffer = null;

        try{
            if (mAlias==null||mAlias.isEmpty()){
                return false;
            }
            if(!mKeyStore.containsAlias(mAlias)){
                return false;
            }
            KeyStore.PrivateKeyEntry privateKeyEntry=(KeyStore.PrivateKeyEntry) mKeyStore.getEntry(mAlias,null);

            Cipher output=Cipher.getInstance("RSA/ECB/PKCS1Padding");
            output.init(Cipher.DECRYPT_MODE,privateKeyEntry.getPrivateKey());


            FileInputStream fis = new FileInputStream(new File(srcFile));
            FileOutputStream fos = new FileOutputStream(new File(destionFile));

            while ((len = fis.read(buffer)) != -1) {
                plainbuffer = output.update(buffer, 0, len);
                fos.write(plainbuffer);
                fos.flush();
            }

            plainbuffer = output.doFinal();
            fos.write(plainbuffer);
            fos.flush();

            if (fis != null)
                fis.close();
            if (fos != null)
                fos.close();
//            CipherInputStream cipherInputStream=new CipherInputStream(new ByteArrayInputStream(Base64.decode(cipherText,
//                    Base64.DEFAULT)), output);
//            ArrayList<Byte> values=new ArrayList<>();
//            int nextByte;
//            while ((nextByte = cipherInputStream.read()) != -1) {
//                values.add((byte)nextByte);
//            }
//
//            byte[] bytes = new byte[values.size()];
//            for(int i = 0; i < bytes.length; i++) {
//                bytes[i] = values.get(i).byteValue();
//            }
//
//            String finalText = new String(bytes, 0, bytes.length, "UTF-8");
            return true;
        }catch (Exception e){
            Toast.makeText(mContext,"Exception " + e.getMessage() + " occured", Toast.LENGTH_LONG).show();
            Log.e(TAG, Log.getStackTraceString(e));
            return false;
        }
    }

    public void deleteKey(final String alias){
        try {
            mKeyStore.deleteEntry(alias);
        } catch (KeyStoreException e) {
            e.printStackTrace();
            Log.e(TAG, Log.getStackTraceString(e));
        }
    }
    public String getAlias() {
        return mAlias;
    }
    public void setAlias(String alias) {
        mAlias = alias;
    }
}
