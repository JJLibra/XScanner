package com.example.myapplication;

import android.graphics.Color;
import android.os.Bundle;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.constraintlayout.widget.ConstraintLayout;

import com.hitomi.cmlibrary.CircleMenu;
import com.hitomi.cmlibrary.OnMenuSelectedListener;
import com.hitomi.cmlibrary.OnMenuStatusChangeListener;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = "MainActivity";
    CircleMenu circleMenu;
    ConstraintLayout constraintLayout;
    private int selectedMenuIndex = -1; // 记录当前选择的菜单项索引

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        circleMenu = findViewById(R.id.user_circle_menu);
        constraintLayout = findViewById(R.id.constraint_layout_user);

        circleMenu.setMainMenu(Color.parseColor("#CDCDCD"), R.mipmap.ic_menu, R.mipmap.ic_cancel)
                .addSubMenu(Color.parseColor("#88bef5"), R.mipmap.ic_home)
                .addSubMenu(Color.parseColor("#83e85a"), R.mipmap.ic_key)
                .addSubMenu(Color.parseColor("#ff4b32"), R.mipmap.ic_setting)
                .addSubMenu(Color.parseColor("#ba53de"), R.mipmap.ic_refresh)
                .addSubMenu(Color.parseColor("#ff8a5c"), R.mipmap.ic_logout)
                .setOnMenuSelectedListener(new OnMenuSelectedListener() {
                    @Override
                    public void onMenuSelected(int index) {
                        selectedMenuIndex = index; // 记录当前选择的按钮索引
                    }
                })
                .setOnMenuStatusChangeListener(new OnMenuStatusChangeListener() {
                    @Override
                    public void onMenuOpened() {
                        // 菜单打开时的操作
                    }

                    @Override
                    public void onMenuClosed() {
                        // 菜单关闭时的操作
                        handleMenuAction(selectedMenuIndex);
                    }
                });
    }

    private void handleMenuAction(int index) {
        switch (index) {
            case 0:
                Toast.makeText(MainActivity.this, "home", Toast.LENGTH_SHORT).show();
                constraintLayout.setBackgroundColor(Color.parseColor("#ecfffb"));
                break;
            case 1:
                Toast.makeText(MainActivity.this, "key", Toast.LENGTH_SHORT).show();
                constraintLayout.setBackgroundColor(Color.parseColor("#96f7d2"));
                break;
            case 2:
                Toast.makeText(MainActivity.this, "setting", Toast.LENGTH_SHORT).show();
                constraintLayout.setBackgroundColor(Color.parseColor("#fac4a2"));
                break;
            case 3:
                Toast.makeText(MainActivity.this, "change", Toast.LENGTH_SHORT).show();
                constraintLayout.setBackgroundColor(Color.parseColor("#d3cde6"));
                break;
            case 4:
                Toast.makeText(MainActivity.this, "logout", Toast.LENGTH_SHORT).show();
                constraintLayout.setBackgroundColor(Color.parseColor("#fff591"));
                break;
        }
    }
}
