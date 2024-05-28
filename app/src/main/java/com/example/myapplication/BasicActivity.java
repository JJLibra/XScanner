package com.example.myapplication;

import android.os.AsyncTask;
import android.os.Bundle;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.util.Log;

import androidx.appcompat.app.AppCompatActivity;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;

public class BasicActivity extends AppCompatActivity {

    private EditText etSubnet;
    private TextView tvResults;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_basic);

        etSubnet = findViewById(R.id.et_subnet);
        tvResults = findViewById(R.id.tv_results);
        Button btnScanNetwork = findViewById(R.id.btn_scan_network);

        btnScanNetwork.setOnClickListener(v -> {
            String subnet = etSubnet.getText().toString();
            new NetworkScanTask(tvResults).execute(subnet);
        });
    }

    private static class NetworkScanTask extends AsyncTask<String, String, List<String>> {

        private TextView tvResults;

        public NetworkScanTask(TextView tvResults) {
            this.tvResults = tvResults;
        }

        @Override
        protected void onPreExecute() {
            super.onPreExecute();
            tvResults.setText("Scanning...\n");
        }

        @Override
        protected List<String> doInBackground(String... params) {
            String subnet = params[0];
            List<String> aliveHosts = new ArrayList<>();
            for (int i = 1; i < 255; i++) {
                String host = subnet + "." + i;
                if (isHostAlive(host)) {
                    publishProgress(host);
                    aliveHosts.add(host);
                }
            }
            return aliveHosts;
        }

        @Override
        protected void onProgressUpdate(String... values) {
            tvResults.append("Host alive: " + values[0] + "\n");
        }

        @Override
        protected void onPostExecute(List<String> result) {
            tvResults.append("Scan complete. Alive hosts:\n");
            for (String host : result) {
                tvResults.append(host + "\n");
            }
        }

        private boolean isHostAlive(String host) {
            try {
                InetAddress address = InetAddress.getByName(host);
                boolean reachable = address.isReachable(1000);  // Timeout in milliseconds
                Log.d("NetworkScanner", "Host " + host + " is reachable: " + reachable);
                return reachable;
            } catch (Exception e) {
                e.printStackTrace();
                return false;
            }
        }
    }
}
