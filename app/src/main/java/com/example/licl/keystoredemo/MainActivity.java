package com.example.licl.keystoredemo;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import com.example.licl.keystoredemo.utils.KeyStoreUtil;

import butterknife.BindView;
import butterknife.ButterKnife;
import butterknife.OnClick;

public class MainActivity extends AppCompatActivity {
    private KeyStoreUtil mKeyStoreUtil;

    @BindView(R.id.encrypt)
    Button encrypt_button;
    @BindView(R.id.decrypt)
    Button decrypt_button;
    @BindView(R.id.set_alias_bt)
    Button set_alias_bt;
    @BindView(R.id.alias_et)
    EditText alias_et;
    @BindView(R.id.pre_text)
    EditText pre_text_et;
    @BindView(R.id.finish_text)
    EditText finish_tv;
    @BindView(R.id.encrypt_file_bt)
    Button encrypt_file_bt;
    @BindView(R.id.decrypt_file_bt)
    Button decrypt_file_bt;
    private String mAlias=null;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        ButterKnife.bind(this);
        mKeyStoreUtil= new KeyStoreUtil(this);
    }

    @OnClick(R.id.set_alias_bt)
    public void setAlias(){
        mAlias=alias_et.getText().toString();
        if(mAlias.isEmpty()){
            Toast.makeText(this,"please input your alias.",
                    Toast.LENGTH_LONG).show();
            return;
        }
        mKeyStoreUtil.setAlias(mAlias);
        mKeyStoreUtil.createNewKeys();
    }
    @OnClick(R.id.encrypt)
    public void encryptString(){
        String handledText="handledText";
        String initalText=pre_text_et.getText().toString();
        if(initalText.isEmpty()){
            Toast.makeText(this,"please input your text for encrypt.",
                    Toast.LENGTH_LONG).show();
            return;
        }else{
//            handledText=mKeyStoreUtil.encryptString(initalText);
            finish_tv.setText(handledText);
        }


    }
    @OnClick(R.id.decrypt)
    public void decryptString(){
        String handledText="handledText";
        String initalText=finish_tv.getText().toString();
        if(initalText.isEmpty()){
            Toast.makeText(this,"there is no text to decode.",
                    Toast.LENGTH_LONG).show();
            return;
        }

//        handledText= Base64.encodeToString(mKeyStoreUtil.decryptString(initalText)
//                ,Base64.DEFAULT);
        pre_text_et.setText(handledText);
    }

    @OnClick(R.id.encrypt_file_bt)

    public void encryptFile(){
//        Toast.makeText(MainActivity.this,"开始加密",Toast.LENGTH_SHORT).show();
        new Thread(){
            @Override
            public void run() {
                Log.i("MainActivity","开始加密");
                String srcFile="/storage/emulated/0/security/photos/2/keystoretest.jpg";
                String desFile="/storage/emulated/0/security/photos/2/keystoretest.cip";
                mKeyStoreUtil.encryptAES(srcFile,desFile);
            }
        }.start();

    }
    @OnClick(R.id.decrypt_file_bt)
    public void decryptFile(){
//        Toast.makeText(MainActivity.this,"开始解密",Toast.LENGTH_SHORT).show();
        new Thread(){
            @Override
            public void run() {
                Log.i("MainActivity","开始解密");
                String srcFile="/storage/emulated/0/security/photos/2/keystoretest.cip";
                String desFile="/storage/emulated/0/security/photos/2/keystoretest2.jpg";
                mKeyStoreUtil.decryptAES(srcFile,desFile);
            }
        }.start();

    }
}
