package com.example.licl.keystoredemo.utils;

import android.content.Context;

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



    public String getIv() {
        return iv;
    }

    public void setIv(String iv) {
        this.iv = iv;
    }

    public String getAESKey() {
        return AESKey;
    }

    public void setAESKey(String AESKey) {
        this.AESKey = AESKey;
    }

    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }




}
