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
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.security.auth.x500.X500Principal;

//before use this util you should excute the "createNewKeys()" method.

public class CryptAESUtils {

    private KeyStore mKeyStore;
    private static String TAG="KeyStoreUtil";
    private Context mContext=null;




    private String mAlias ="default";

    @RequiresApi(api = Build.VERSION_CODES.M)
    public CryptAESUtils(Context context){

        mContext=context;

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


    //创建新的公私钥
    @RequiresApi(api = Build.VERSION_CODES.M)
    public void createNewKeys(){
        try{
            if(!mKeyStore.containsAlias(mAlias)){

                KeyGenerator generator= KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,"AndroidKeyStore");
                KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                        mAlias,
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT);

                builder
                        .setKeySize(256)
                        .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7);


                generator.init(builder.build());
                generator.generateKey();
            }
        }catch (Exception e){
            Toast.makeText(mContext,"Exception " + e.getMessage() + " occured", Toast.LENGTH_LONG).show();
            Log.e(TAG, Log.getStackTraceString(e));
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


            Cipher inCipher=Cipher.getInstance("AES/GCM/NoPadding");
            SecretKey secretKey=((KeyStore.SecretKeyEntry)mKeyStore.getEntry(mAlias,null)).getSecretKey();
            inCipher.init(Cipher.ENCRYPT_MODE,secretKey);
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
            //选择AES加密算法进行加密
            Cipher output=Cipher.getInstance("AES/GCM/NoPadding");
            SecretKey secretKey=((KeyStore.SecretKeyEntry)mKeyStore.getEntry(mAlias,null)).getSecretKey();

            output.init(Cipher.DECRYPT_MODE,secretKey);


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
