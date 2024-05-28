package com.example.myapplication;

import android.content.Intent;
import android.os.Bundle;
import android.widget.Button;

import androidx.appcompat.app.AppCompatActivity;
import androidx.constraintlayout.widget.ConstraintLayout;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = "MainActivity";
    ConstraintLayout constraintLayout;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        constraintLayout = findViewById(R.id.constraint_layout_user);
        Button basicButton = findViewById(R.id.basic_button);
        Button deepButton = findViewById(R.id.deep_button);

        basicButton.setOnClickListener(v -> {
            Intent basicIntent = new Intent(this, BasicActivity.class);
            startActivity(basicIntent);
        });

        deepButton.setOnClickListener(v -> {
            Intent deepIntent = new Intent(this, DeepActivity.class);
            startActivity(deepIntent);
        });
    }
}
