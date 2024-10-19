package com.shafiq.nsrg;

import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.example.liboqs.KeyEncapsulation;
import com.example.liboqs.Pair;

import org.json.JSONObject;


import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Enumeration;

public class MainActivity extends AppCompatActivity {

    private EditText editTextServerIP, editTextUserID, editTextPassword;
    private Button buttonLogin;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Initialize the views
        editTextServerIP = findViewById(R.id.editTextServerIP);
        editTextUserID = findViewById(R.id.editTextUserID);
        editTextPassword = findViewById(R.id.editTextPassword);
        buttonLogin = findViewById(R.id.buttonLogin);

        // Set an OnClickListener on the login button
        buttonLogin.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String serverIP = editTextServerIP.getText().toString();
                String userID = editTextUserID.getText().toString();
                String password = editTextPassword.getText().toString();

                if (serverIP.isEmpty() || userID.isEmpty() || password.isEmpty()) {
                    Toast.makeText(MainActivity.this, "Please fill in all fields", Toast.LENGTH_SHORT).show();
                } else {
                    Log.d("MainActivity", "Login button clicked, starting the login thread.");

                    // Run the provided code here
                    new Thread(() -> {
                        try {
                            final String SK;
                            String SID_j = null;
                            String SID_i = null;
                            String SPORT = serverIP;

                            // Start of login phase
                            String gamma_i = hashData(userID + password);
                            System.out.println("Gamma_i value: " + gamma_i);

                            String filename = "rm_i_reg_data.json"; // The file will now be loaded from assets

                            // Read the JSON file
                            JSONObject data = readJsonFile(filename);
                            String mu_i_str2 = data.get("mu_i").toString();
                            System.out.println("Extracted mu_i value: " + mu_i_str2);
//


                            // Extract the values from storage
                            BigInteger mu_i;
                            try {
                                // Extract the value as a string to prevent any floating-point conversion
                                String mu_i_str = data.get("mu_i").toString();
                                mu_i = new BigInteger(mu_i_str);  // Convert directly to BigInteger
                                System.out.println("mu_i (as BigInteger): " + mu_i);
                            } catch (NumberFormatException e) {
                                System.err.println("Error while converting mu_i to BigInteger: " + e.getMessage());
                                e.printStackTrace();
                                return;
                            }
                            String PID_j = data.getString("PID_j");
                            String GCS_pk = data.getString("GCS_pk");
                            String lambda_i = data.getString("lambda_i");

                            // Print the values
                            System.out.println("mu_i: " + mu_i);
                            System.out.println("PID_j: " + PID_j);
                            System.out.println("GCS_pk: " + GCS_pk);
                            System.out.println("lambda_i: " + lambda_i);

                            // Measure memory usage before operation
                            long memBeforeMSG1 = getMemoryUsage();
                            long startCPUTimeMSG1 = System.nanoTime();

                            // Perform calculations to retrieve necessary parameters
                            BigInteger gamma_i_int = new BigInteger(gamma_i, 16);
                            BigInteger combinedDataEthSaltInt = mu_i.xor(gamma_i_int);
                            System.out.println("combined_data_eth_salt_int: " + combinedDataEthSaltInt);

                            byte[] combinedDataEthSaltBytes = combinedDataEthSaltInt.toByteArray();

                            // Split the values
                            String[] retrievedValues = splitValues(combinedDataEthSaltBytes);

                            // Check that we have enough split values to proceed
                            if (retrievedValues.length < 2) {
                                System.err.println("Error: Expected at least 2 values after splitting, but got " + retrievedValues.length);
                                return; // Exit the thread if the expected values are not available
                            }

                            String retrieved_eth_i = retrievedValues[0];
                            String retrieved_salt_i = retrievedValues[1];

                            System.out.println("retrieved_eth_i: " + retrieved_eth_i);
                            System.out.println("retrieved_salt_i: " + retrieved_salt_i);

                            // Compute lambda_i
                            String lambda_i_start = hashData(userID + password + retrieved_eth_i + retrieved_salt_i);
                            if (!lambda_i_start.equals(lambda_i)) {
                                System.out.println("Verification failed: lambda_i_start != lambda_i");
                                return;
                            }
                            System.out.println("Input credentials are verified: The values are equal.");

                            // Get the current IP address
                            try {
                                for (Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces(); en.hasMoreElements(); ) {
                                    NetworkInterface intf = en.nextElement();
                                    for (Enumeration<InetAddress> enumIpAddr = intf.getInetAddresses(); enumIpAddr.hasMoreElements(); ) {
                                        InetAddress inetAddress = enumIpAddr.nextElement();
                                        if (!inetAddress.isLoopbackAddress() && inetAddress instanceof java.net.Inet4Address) {
                                            SID_i = inetAddress.getHostAddress();
                                            System.out.println("Current IP Address: " + SID_i);
                                            break;
                                        }
                                    }
                                    if (SID_i != null) {
                                        break;
                                    }
                                }
                            } catch (SocketException e) {
                                e.printStackTrace();
                            }

                            // Generate random number (n_1)
                            SecureRandom random = new SecureRandom();
                            BigInteger n_1 = new BigInteger(128, random);

                            // Concatenate message values
                            byte[] msg_i = concatenateMsgIValues(userID, SID_i, PID_j, n_1);
                            Log.d("MainActivity", "Concatenated message values: " + new String(msg_i, StandardCharsets.UTF_8));

                            // Convert GCS's public key from hex string to bytes
                            byte[] retrieved_GCS_public_key = hexStringToByteArray(GCS_pk);

                            // Generate a ciphertext and shared secret using Kyber512 KEM
                            String kemName = "Kyber512";
                            KeyEncapsulation RU = new KeyEncapsulation(kemName);

                            // Perform encapsulation to generate ciphertext (CT_i) and shared secret (Chi_i)
                            Pair<byte[], byte[]> encapsulation = RU.encap_secret(retrieved_GCS_public_key);
                            byte[] CT_i = encapsulation.getLeft();
                            byte[] Chi_i = encapsulation.getRight();

                            BigInteger Chi_i_int = new BigInteger(1, Chi_i);
                            BigInteger msg_i_int = new BigInteger(1, msg_i);
                            BigInteger Mi_1 = Chi_i_int.xor(msg_i_int);
                            String Mi_2 = hashData(userID + SID_i + n_1.toString() + retrieved_eth_i);
                            Log.d("MainActivity", "Mi_1: " + Mi_1);
                            Log.d("MainActivity", "Mi_2: " + Mi_2);
                            Log.d("MainActivity", "CT_i: " + new String(CT_i, StandardCharsets.UTF_8));

                            // Prepare JSON data for sending Message 1
                            JSONObject jsonData = new JSONObject();
                            jsonData.put("CT_i", bytesToHex(CT_i));
                            jsonData.put("Mi_1", Mi_1.toString());
                            jsonData.put("Mi_2", Mi_2);
                            byte[] jsonDataBytes = jsonData.toString().getBytes(StandardCharsets.UTF_8);
                            int jsonLength = jsonDataBytes.length;

                            // Step 3: Send data to the server
                            try (Socket socket = new Socket(SPORT, 11111);
                                 OutputStream outputStream = socket.getOutputStream();
                                 InputStream inputStream = socket.getInputStream()) {
                                Log.d("MainActivity", "Sending Message 1 to the server.");

                                outputStream.write(ByteBuffer.allocate(4).putInt(jsonLength).array());
                                outputStream.write(jsonDataBytes);
                                outputStream.flush();
                                System.out.println("Successfully sent Message 1 to GSS: " + jsonData.toString());

                                byte[] buffer = new byte[1024];
                                int bytesRead = inputStream.read(buffer);
                                if (bytesRead != -1) {
                                    String msg4 = new String(buffer, 0, bytesRead, StandardCharsets.UTF_8);
                                    System.out.println("Received (msg4) from Server: " + msg4);

                                    JSONObject jsonMsg4Data = new JSONObject(msg4);
                                    BigInteger received_Mk_3 = new BigInteger(jsonMsg4Data.getString("Mk_3"));
                                    String received_Mk_4 = jsonMsg4Data.getString("Mk_4");

                                    BigInteger retrieved_msg_k_2 = Chi_i_int.xor(received_Mk_3);
                                    byte[] retrieved_msg_k_2_data = retrieved_msg_k_2.toByteArray();
                                    String[] splitValues = splitMsgK2Values(retrieved_msg_k_2_data);

                                    // Check that we have enough split values to proceed
                                    if (splitValues.length < 3) {
                                        System.err.println("Error: Expected at least 3 values after splitting, but got " + splitValues.length);
                                        return; // Exit the thread if the expected values are not available
                                    }

                                    String n_3 = splitValues[0];
                                    String n_4 = splitValues[1];
                                    SID_j = splitValues[2];

                                    System.out.println("n_3: " + n_3);
                                    System.out.println("n_4: " + n_4);
                                    System.out.println("SID_j: " + SID_j);

                                    String Mk_4_star = hashData(userID + n_4 + retrieved_eth_i);
                                    if (!Mk_4_star.equals(received_Mk_4)) {
                                        System.out.println("Verification failed: Mi_2_star != retrieved_Mi_2");
                                        return;
                                    }
                                    System.out.println("GSS Authentication is Successful");

                                    SK = hashData(SID_i + SID_j + PID_j + n_1.toString() + n_3);
                                    System.out.println("Establishes SK: " + SK);

                                    // Add an intent to start the VideoStreamActivity
                                    runOnUiThread(() -> {
                                        // Start VideoStreamActivity once SK is successfully established
                                        Intent intent = new Intent(MainActivity.this, VideoStreamActivity.class);
                                        intent.putExtra("sharedKey", SK);
                                        intent.putExtra("serverAddress", serverIP);
                                        intent.putExtra("port", 22222); // Assuming this is the default port for streaming
                                        startActivity(intent);
                                    });
                                }
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }).start();
                }
            }
        });
    }

    private JSONObject readJsonFile(String filename) {
        try {
            // Access the file from assets
            InputStream inputStream = getAssets().open(filename);
            int size = inputStream.available();
            byte[] buffer = new byte[size];
            inputStream.read(buffer);
            inputStream.close();
            String json = new String(buffer, StandardCharsets.UTF_8);
            return new JSONObject(json);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private String[] splitValues(byte[] combinedDataEthSaltBytes) {
        String decodedData = new String(combinedDataEthSaltBytes, StandardCharsets.UTF_8);
        return decodedData.split(":");
    }

    private byte[] concatenateMsgIValues(String userID, String sidI, String pidJ, BigInteger n1) {
        String concatenatedString = userID + ":" + sidI + ":" + pidJ + ":" + n1.toString();
        return concatenatedString.getBytes(StandardCharsets.UTF_8);
    }

    private byte[] hexStringToByteArray(String gcsPk) {
        int len = gcsPk.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(gcsPk.charAt(i), 16) << 4)
                    + Character.digit(gcsPk.charAt(i + 1), 16));
        }
        return data;
    }

    private String[] splitMsgK2Values(byte[] retrievedMsgK2Data) {
        String decodedData = new String(retrievedMsgK2Data, StandardCharsets.UTF_8);
        return decodedData.split(":");
    }

    private String hashData(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = md.digest(s.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    private String bytesToHex(byte[] hashBytes) {
        StringBuilder hexString = new StringBuilder(2 * hashBytes.length);
        for (byte b : hashBytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    private long getMemoryUsage() {
        Runtime runtime = Runtime.getRuntime();
        return runtime.totalMemory() - runtime.freeMemory();
    }
}
