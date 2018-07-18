package com.example.licl.keystoredemo;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
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
    @BindView(R.id.pre_text)
    EditText pre_text_et;
    @BindView(R.id.finish_text)
    TextView finish_tv;
    final String mAlias ="first_keystore_demo";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        ButterKnife.bind(this);
        mKeyStoreUtil=new KeyStoreUtil(this,mAlias);
        mKeyStoreUtil.createNewKeys();
    }
    @OnClick(R.id.encrypt)
    public void encryptString(){
        String handledText="handledText";
        String initalText=pre_text_et.getText().toString();
        if(initalText.isEmpty()){
            Toast.makeText(this,"please input your text for encrypt.",
                    Toast.LENGTH_LONG).show();

        }else{
            handledText=mKeyStoreUtil.encryptString(initalText);
        }
        finish_tv.setText(handledText);

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

        handledText=mKeyStoreUtil.decryptString(initalText);
        pre_text_et.setText(handledText);
    }
}
