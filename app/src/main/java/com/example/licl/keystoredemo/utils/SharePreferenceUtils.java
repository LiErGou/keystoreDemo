package com.example.licl.keystoredemo.utils;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;

public class SharePreferenceUtils {
    private static final String AES_IV="iv";
    private static final String AES_KEY="AESKey";
    private static final String RSA_ALIAS="alias";
    private String iv;
    private String AESKey;
    private String alias;
    private Context mContext;
    private SharedPreferences mSharedPreferences;
    private SharedPreferences.Editor mEditor;

    public static SharePreferenceUtils getSharePreferenceUtils(Context context){
        return new SharePreferenceUtils(context);
    }
    private SharePreferenceUtils (Context context){

        mContext=context;
        mSharedPreferences=mContext.getSharedPreferences("AESvalues",Context.MODE_PRIVATE);
        mEditor=mSharedPreferences.edit();
    }

    public boolean save(){
        if (iv!=null&&AESKey!=null&&alias!=null){
            mEditor.putString(AES_IV,this.iv);
            mEditor.putString(AES_KEY,this.AESKey);
            mEditor.putString(RSA_ALIAS,this.alias);
            mEditor.commit();
            return true;
        }
        return false;
    }



    public byte[] getIv() {
//        if(iv!=null){
//            return Base64.decode(iv,Base64.DEFAULT);
//        }
        String ivFromSP=mSharedPreferences.getString(AES_IV,null);
        if(ivFromSP==null) return null;
        return Base64.decode(ivFromSP,Base64.DEFAULT);
    }

    public void setIv(byte[] iv) {
        this.iv = Base64.encodeToString(iv,Base64.DEFAULT);
    }

    public byte[] getAESKey() {
//        if(AESKey!=null){
//            return Base64.decode(AESKey,Base64.DEFAULT);
//        }

        String AESKeyFromSP=mSharedPreferences.getString(AES_KEY,null);
        if(AESKeyFromSP==null) return null;
        return Base64.decode(AESKeyFromSP,Base64.DEFAULT);
    }

    public void setAESKey(byte[] AESKey) {
        this.AESKey = Base64.encodeToString(AESKey,Base64.DEFAULT);
    }

    public String getAlias() {
//        if(alias!=null){
//            return alias;
//        }
        return mSharedPreferences.getString(RSA_ALIAS,null);
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }

}
