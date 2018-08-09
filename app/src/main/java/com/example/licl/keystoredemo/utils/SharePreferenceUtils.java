package com.example.licl.keystoredemo.utils;

import android.content.Context;
import android.util.Base64;

public class SharePreferenceUtils {
    private String iv;
    private String AESKey;
    private String alias;
    private Context mContext;

    public static SharePreferenceUtils getSharePreferenceUtils(Context context){
        return new SharePreferenceUtils(context);
    }
    private SharePreferenceUtils (Context context){
        mContext=context;
    }

    public boolean save(){
        return false;
    }



    public byte[] getIv() {
        return Base64.decode(iv,Base64.DEFAULT);
    }

    public void setIv(byte[] iv) {
        this.iv = Base64.encodeToString(iv,Base64.DEFAULT);
    }

    public byte[] getAESKey() {
        return Base64.decode(AESKey,Base64.DEFAULT);
    }

    public void setAESKey(byte[] AESKey) {
        this.AESKey = Base64.encodeToString(AESKey,Base64.DEFAULT);;
    }

    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }




}
