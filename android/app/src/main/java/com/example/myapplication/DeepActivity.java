package com.example.myapplication;

import android.os.AsyncTask;
import android.os.Bundle;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

public class DeepActivity extends AppCompatActivity {

    private EditText etIpAddress;
    private EditText etStartPort;
    private EditText etEndPort;
    private TextView tvResults;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_deep);

        etIpAddress = findViewById(R.id.et_ip_address);
        etStartPort = findViewById(R.id.et_start_port);
        etEndPort = findViewById(R.id.et_end_port);
        tvResults = findViewById(R.id.tv_results);
        Button btnScanPorts = findViewById(R.id.btn_scan_ports);

        btnScanPorts.setOnClickListener(v -> {
            String ipAddress = etIpAddress.getText().toString();
            int startPort = Integer.parseInt(etStartPort.getText().toString());
            int endPort = Integer.parseInt(etEndPort.getText().toString());
            new PortScanTask(ipAddress, startPort, endPort, tvResults).execute();
        });
    }

    private static class PortScanTask extends AsyncTask<Void, Integer, List<Integer>> {

        private String host;
        private int startPort;
        private int endPort;
        private TextView tvResults;

        public PortScanTask(String host, int startPort, int endPort, TextView tvResults) {
            this.host = host;
            this.startPort = startPort;
            this.endPort = endPort;
            this.tvResults = tvResults;
        }

        @Override
        protected void onPreExecute() {
            super.onPreExecute();
            tvResults.setText("Scanning...\n");
        }

        @Override
        protected List<Integer> doInBackground(Void... voids) {
            List<Integer> openPorts = new ArrayList<>();
            for (int port = startPort; port <= endPort; port++) {
                try (Socket socket = new Socket()) {
                    socket.connect(new InetSocketAddress(host, port), 100);
                    openPorts.add(port);
                    publishProgress(port);
                } catch (IOException ignored) {
                }
            }
            return openPorts;
        }

        @Override
        protected void onProgressUpdate(Integer... values) {
            tvResults.append("Port " + values[0] + " is open\n");
        }

        @Override
        protected void onPostExecute(List<Integer> result) {
            tvResults.append("Scan complete. Open ports:\n");
            for (int port : result) {
                tvResults.append(port + "\n");
            }
        }
    }
}
