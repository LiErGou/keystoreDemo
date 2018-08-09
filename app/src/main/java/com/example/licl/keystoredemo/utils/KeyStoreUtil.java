package com.example.licl.keystoredemo.utils;

import android.content.Context;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.RequiresApi;
import android.util.Log;
import android.widget.Toast;

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
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Calendar;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

//before use this util you should excute the "createNewKeys()" method.

public class KeyStoreUtil {

    private static final String AES_MODE = "AES/GCM/NoPadding";
    private static final String RSA_MODE = "RSA/ECB/PKCS1Padding";
    private static final String KEYSTORE_PROVIDER = "AndroidKeyStore";
    private KeyStore mKeyStore;
    private static String TAG="KeyStoreUtil";
    private Context mContext;
    private SharePreferenceUtils mSharePreferenceUtils;


    //TODO 让mAlias能够更新且不重复
    private String mAlias ="default";

    public KeyStoreUtil(Context context){

        mContext=context;
        mSharePreferenceUtils=SharePreferenceUtils.getSharePreferenceUtils(context);
        init();
        if(!isAESExsit()){
            createNewKeys();
        }

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


    //创建新RSA的秘钥
    public void createNewKeys(){
        if(Build.VERSION.SDK_INT>=Build.VERSION_CODES.M){
            try {
                generateRSAKey_AboveApi23();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }else{
            createNewKeys_BlewApi23();
        }
        genAESKey();
    }

    //使用AES对文件进行加密
    public boolean encryptAES(String srcFile,
                              String destionFile){

        int len = 0;
        byte[] buffer = new byte[5*1024];
        try{

            Cipher inCipher=Cipher.getInstance(AES_MODE);
            byte[] iv=mSharePreferenceUtils.getIv();

            inCipher.init(Cipher.ENCRYPT_MODE,getAESKey(),new IvParameterSpec(iv));

            //找到源文件路径以及目标文件路径
            FileInputStream fis = new FileInputStream(new File(srcFile));
            File desFile=new File(destionFile);
            FileOutputStream fos = null;
            CipherOutputStream out = null;
            fos=new FileOutputStream(desFile,true);
            out=new CipherOutputStream(fos, inCipher);
            while ((len = fis.read(buffer)) != -1) {
                //对目标文件流加密

                out.write(buffer,0,len);
                out.flush();

            }
            out.close();
            if (fis != null)
                fis.close();
            return true;
        }catch (Exception e){
            e.printStackTrace();
            Log.e(TAG, Log.getStackTraceString(e));
            return false;
        }
    }


    //使用AES对加密过的文件进行解密
    public boolean decryptAES(String srcFile,
                              String destionFile){
        int len = 0;
        byte[] buffer = new byte[5*1024];
        try{
            Cipher output=Cipher.getInstance(AES_MODE);
            byte[] iv=mSharePreferenceUtils.getIv();

            output.init(Cipher.DECRYPT_MODE,getAESKey(),new IvParameterSpec(iv));


            FileInputStream fis = new FileInputStream(new File(srcFile));

            File desFile=new File(destionFile);
            FileOutputStream fos =null;
            CipherOutputStream out=null;
            fos = new FileOutputStream(desFile,true);
            //目标输出流包裹一层加密层
            out=new CipherOutputStream(fos, output);
            while ((len = fis.read(buffer)) >= 0) {
                out.write(buffer, 0, len);
                out.flush();
            }

            out.close();
            fis.close();
            return true;
        }catch (Exception e){

            Log.e(TAG, Log.getStackTraceString(e));
            return false;
        }
    }

    //api高于23 RSA生成秘钥方式
    @RequiresApi(api = Build.VERSION_CODES.M)
    private void generateRSAKey_AboveApi23() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator
                .getInstance(KeyProperties.KEY_ALGORITHM_RSA, KEYSTORE_PROVIDER);
        KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec
                .Builder(mAlias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                .build();

        keyPairGenerator.initialize(keyGenParameterSpec);
        keyPairGenerator.generateKeyPair();

    }
    //api低于23 RSA生成秘钥
    private void createNewKeys_BlewApi23(){
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

    private boolean isAESExsit(){
        boolean hasIv=mSharePreferenceUtils.getIv()!=null;
        boolean hasKey=mSharePreferenceUtils.getAESKey()!=null;
        boolean hasAlias=mSharePreferenceUtils.getAlias()!=null;
        return hasAlias && hasIv && hasKey;
    }
    //生成AES秘钥以及iv，并对秘钥加密，对他们持久化存储
    private void genAESKey(){
        if(isAESExsit()){
            return;
        }
        byte[] aesKey=new byte[16];
        SecureRandom secureRandom=new SecureRandom();
        secureRandom.nextBytes(aesKey);     //生成AESKey

        byte[] iv=secureRandom.generateSeed(12);    //生成iv



        if(iv!=null&&iv.length!=0){
            mSharePreferenceUtils.setIv(iv);
        }else{
            Log.e(TAG,"genAESKey Failed iv is null !");
            return;
        }


        byte[] encryptedAESKey=encryptString(aesKey);
        if(encryptedAESKey!=null&&encryptedAESKey.length!=0){
            mSharePreferenceUtils.setAESKey(encryptedAESKey);
        }else{
            Log.e(TAG,"genAESKey Failed iv is null !");
            return;
        }


        if(mAlias!=null&&mAlias.length()!=0){
            mSharePreferenceUtils.setAlias(mAlias);
        }else{
            Log.e(TAG,"genAESKey Failed iv is null !");
            return;
        }
        mSharePreferenceUtils.save();
    }


    //从sp中读出使用RSA加密后的AESkey，并将其解密
    private SecretKeySpec getAESKey(){
        byte[] encryptedKey=mSharePreferenceUtils.getAESKey();
        mAlias=mSharePreferenceUtils.getAlias();
        byte[] aesKey=decryptString(encryptedKey);

        return new SecretKeySpec(aesKey,AES_MODE);
    }




    //使用RSA对byte[]加密的方法
    private byte[] encryptString(byte[] initialText){
        try{
            //alias对应的秘钥不存在
            if (mAlias==null||mAlias.isEmpty()){
                return null;
            }
            //秘钥库中不存在alias
            if(!mKeyStore.containsAlias(mAlias)){
                return null;
            }
            KeyStore.PrivateKeyEntry privateKeyEntry=(KeyStore.PrivateKeyEntry) mKeyStore.getEntry(mAlias,null);
            RSAPublicKey publicKey=(RSAPublicKey) privateKeyEntry.getCertificate().getPublicKey();

            Cipher inCipher=Cipher.getInstance(RSA_MODE, "AndroidOpenSSL");
            inCipher.init(Cipher.ENCRYPT_MODE,publicKey);

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            CipherOutputStream cipherOutputStream = new CipherOutputStream(
                    outputStream, inCipher);
            cipherOutputStream.write(initialText);
            cipherOutputStream.close();
            byte [] vals = outputStream.toByteArray();
            return vals;
        }catch (Exception e){
            e.printStackTrace();
            Log.e(TAG, Log.getStackTraceString(e));
            return null;
        }
    }


    //使用RSA对bute[]解密的方法
    private byte[] decryptString(byte[] cipherText){

        try{
            if (mAlias==null||mAlias.isEmpty()){
                return null;
            }
            if(!mKeyStore.containsAlias(mAlias)){
                return null;
            }
            KeyStore.PrivateKeyEntry privateKeyEntry=(KeyStore.PrivateKeyEntry) mKeyStore.getEntry(mAlias,null);

            Cipher output=Cipher.getInstance(RSA_MODE);
            output.init(Cipher.DECRYPT_MODE,privateKeyEntry.getPrivateKey());

            CipherInputStream cipherInputStream=new CipherInputStream(new ByteArrayInputStream(cipherText), output);
            ArrayList<Byte> values=new ArrayList<>();
            int nextByte;
            while ((nextByte = cipherInputStream.read()) != -1) {
                values.add((byte)nextByte);
            }

            byte[] bytes = new byte[values.size()];
            for(int i = 0; i < bytes.length; i++) {
                bytes[i] = values.get(i).byteValue();
            }

            return bytes;
        }catch (Exception e){

            Log.e(TAG, Log.getStackTraceString(e));
            return null;
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
