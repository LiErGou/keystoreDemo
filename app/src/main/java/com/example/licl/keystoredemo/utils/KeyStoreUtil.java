package com.example.licl.keystoredemo.utils;

import android.content.Context;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.RequiresApi;
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
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

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
    private Context mContext=null;
    private SharePreferenceUtils mSharePreferenceUtils;



    private String mAlias ="default";

    public KeyStoreUtil(Context context){

        mContext=context;
        mSharePreferenceUtils=SharePreferenceUtils.getSharePreferenceUtils(context);
        init();
        createNewKeys();
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


    //创建新的秘钥
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
    //api高于23生成秘钥方式
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
    //api低于23生成秘钥
    public void createNewKeys_BlewApi23(){
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


    private void genAESKey(){
        byte[] aesKey=new byte[16];
        SecureRandom secureRandom=new SecureRandom();
        secureRandom.nextBytes(aesKey);

        byte[] generated=secureRandom.generateSeed(12);

        //TODO 需要将iv做持久化
        String iv=Base64.encodeToString(generated,Base64.DEFAULT);
        if(iv!=null&&iv.length()!=0){
            mSharePreferenceUtils.setIv(iv);
        }else{
            Log.e(TAG,"genAESKey Failed iv is null !");
            return;
        }

        //TODO 对加密过的AESKEY做持久化
        String encryptedAESKey=encryptString(Base64.encodeToString(aesKey,Base64.DEFAULT));
        if(encryptedAESKey!=null&&encryptedAESKey.length()!=0){
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


    //从sp中读出AESkey
    private SecretKeySpec getAESKey(){
        String encryptedKey=mSharePreferenceUtils.getAESKey();
        byte[] aesKey=decryptString(encryptedKey);

        return new SecretKeySpec(aesKey,AES_MODE);
    }

    public boolean encryptAES(String srcFile,
                              String destionFile){

        int len = 0;
        byte[] buffer = new byte[128];
        try{

            Cipher inCipher=Cipher.getInstance(AES_MODE);
            String iv=mSharePreferenceUtils.getIv();
            byte[] iv_bytes=Base64.decode(iv,Base64.DEFAULT);
            inCipher.init(Cipher.ENCRYPT_MODE,getAESKey(),new IvParameterSpec(iv_bytes));

            //找到源文件路径以及目标文件路径
            FileInputStream fis = new FileInputStream(new File(srcFile));
            File desFile=new File(destionFile);
            FileOutputStream fos = null;
            CipherOutputStream out = null;

            while ((len = fis.read(buffer)) != -1) {
                //对目标文件流加密
                fos=new FileOutputStream(desFile,true);
                out=new CipherOutputStream(fos, inCipher);
                out.write(buffer,0,len);
                out.flush();
                out.close();
            }

            if (fis != null)
                fis.close();
            return true;
        }catch (Exception e){
            e.printStackTrace();
            Log.e(TAG, Log.getStackTraceString(e));
            return false;
        }
    }

    public boolean decryptAES(String srcFile,
                               String destionFile){
        int len = 0;
        byte[] buffer = new byte[256];
        byte[] plainbuffer = null;
        try{

            //选择RSA加密算法进行加密
            Cipher output=Cipher.getInstance(AES_MODE);
            String iv=mSharePreferenceUtils.getIv();
            byte[] iv_bytes=Base64.decode(iv,Base64.DEFAULT);
            output.init(Cipher.DECRYPT_MODE,getAESKey(),new IvParameterSpec(iv_bytes));


            FileInputStream fis = new FileInputStream(new File(srcFile));

            File desFile=new File(destionFile);
            FileOutputStream fos =null;
            CipherOutputStream out=null;
            while ((len = fis.read(buffer)) >= 0) {
                fos = new FileOutputStream(desFile,true);
                //目标输出流包裹一层加密层
                out=new CipherOutputStream(fos, output);
                out.write(buffer, 0, len);
                out.flush();
                out.close();
            }
            fis.close();
            return true;
        }catch (Exception e){
            Toast.makeText(mContext,"Exception " + e.getMessage() + " occured", Toast.LENGTH_LONG).show();
            Log.e(TAG, Log.getStackTraceString(e));
            return false;
        }
    }


    //使用秘钥对字符串加密
    public String encryptString(String initialText){
        try{
            //alias对应的秘钥不存在
            if (mAlias==null||mAlias.isEmpty()){
                return "alias is null or empty";
            }
            //秘钥库中不存在alias
            if(!mKeyStore.containsAlias(mAlias)){
                return "keystore does not contain alias";
            }
            KeyStore.PrivateKeyEntry privateKeyEntry=(KeyStore.PrivateKeyEntry) mKeyStore.getEntry(mAlias,null);
            RSAPublicKey publicKey=(RSAPublicKey) privateKeyEntry.getCertificate().getPublicKey();

            Cipher inCipher=Cipher.getInstance(RSA_MODE, "AndroidOpenSSL");
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

    public byte[] decryptString(String cipherText){

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
            return bytes;
        }catch (Exception e){
            Toast.makeText(mContext,"Exception " + e.getMessage() + " occured", Toast.LENGTH_LONG).show();
            Log.e(TAG, Log.getStackTraceString(e));
            return null;
        }
    }
    //使用密钥对文件进行加密
    public boolean encryptFile(String srcFile,
                              String destionFile){
        int len = 0;
        byte[] buffer = new byte[128];

        try{
            //alias对应的秘钥不存在
            if (mAlias==null||mAlias.isEmpty()){
                return false;
            }
            //密钥库中不存在alias
            if(!mKeyStore.containsAlias(mAlias)){
                return false;
            }
            KeyStore.PrivateKeyEntry privateKeyEntry=(KeyStore.PrivateKeyEntry
                    ) mKeyStore.getEntry(mAlias,null);
            RSAPublicKey publicKey=(RSAPublicKey)
                    privateKeyEntry.getCertificate().getPublicKey();
            //选择RSA加密算法进行加密
            Cipher inCipher=Cipher.getInstance(RSA_MODE, "AndroidOpenSSL");
            inCipher.init(Cipher.ENCRYPT_MODE,publicKey);
            //找到源文件路径以及目标文件路径
            FileInputStream fis = new FileInputStream(new File(srcFile));
            File desFile=new File(destionFile);
            FileOutputStream fos = null;
            CipherOutputStream out = null;

            while ((len = fis.read(buffer)) != -1) {
                //对目标文件流加密
                fos=new FileOutputStream(desFile,true);
                out=new CipherOutputStream(fos, inCipher);
                out.write(buffer,0,len);
                out.flush();
                out.close();
            }

            if (fis != null)
                fis.close();
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
        byte[] buffer = new byte[256];
        byte[] plainbuffer = null;
        try{
            if (mAlias==null||mAlias.isEmpty()){
                return false;
            }
            if(!mKeyStore.containsAlias(mAlias)){
                return false;
            }
            KeyStore.PrivateKeyEntry privateKeyEntry=(KeyStore.PrivateKeyEntry) mKeyStore.getEntry(mAlias,null);
            //选择RSA加密算法进行加密
            Cipher output=Cipher.getInstance(RSA_MODE);
            output.init(Cipher.DECRYPT_MODE,privateKeyEntry.getPrivateKey());


            FileInputStream fis = new FileInputStream(new File(srcFile));

            File desFile=new File(destionFile);
            FileOutputStream fos =null;
            CipherOutputStream out=null;
            while ((len = fis.read(buffer)) >= 0) {
                fos = new FileOutputStream(desFile,true);
                //目标输出流包裹一层加密层
                out=new CipherOutputStream(fos, output);
                out.write(buffer, 0, len);
                out.flush();
                out.close();
            }
            fis.close();
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
