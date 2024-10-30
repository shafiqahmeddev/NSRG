package com.shafiq.nsrg;

import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Canvas;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.SurfaceHolder;
import android.view.SurfaceView;

import androidx.appcompat.app.AppCompatActivity;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;

public class VideoStreamActivity extends AppCompatActivity {

    private static final String TAG = "VideoStreamActivity";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String AES_ALGORITHM = "AES";
    private static final int GCM_TAG_LENGTH = 16 * 8; // In bits (128 bits)
    private static final int MAX_PACKET_SIZE = 65535;

    private static final int FIXED_FRAME_SIZE = 640 * 480 * 3; // Assuming a fixed frame size for consistency

    private ExecutorService executorService = Executors.newSingleThreadExecutor();
    private SurfaceView surfaceView;
    private DatagramSocket socket;
    private byte[] sharedKey;
    private String serverAddress;
    private int port;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_video_stream);

        // Retrieve the shared key and server details from the intent
        Intent intent = getIntent();
        String encodedKey = intent.getStringExtra("sharedKey");
        serverAddress = intent.getStringExtra("serverAddress");
        port = intent.getIntExtra("port", 11111);

        if (encodedKey == null || encodedKey.isEmpty()) {
            Log.e(TAG, "Shared key is null or empty. Cannot proceed with key exchange.");
            return;
        }

        try {
            // Decode the shared key from Base64
            byte[] rawKey = Base64.decode(encodedKey, Base64.DEFAULT);

            // Ensure the shared key is a valid AES key length (16, 24, or 32 bytes)
            if (rawKey.length >= 32) {
                sharedKey = Arrays.copyOf(rawKey, 32); // Use 256-bit key
            } else if (rawKey.length >= 24) {
                sharedKey = Arrays.copyOf(rawKey, 24); // Use 192-bit key
            } else {
                sharedKey = Arrays.copyOf(rawKey, 16); // Use 128-bit key
            }

            Log.d(TAG, "Decoded and resized Shared Key: " + bytesToHex(sharedKey));
        } catch (Exception e) {
            Log.e(TAG, "Failed to decode shared key: " + e.getMessage(), e);
            return;
        }

        surfaceView = findViewById(R.id.surfaceView);
        SurfaceHolder holder = surfaceView.getHolder();

        holder.addCallback(new SurfaceHolder.Callback() {
            @Override
            public void surfaceCreated(SurfaceHolder surfaceHolder) {
                // Start the key exchange and video streaming on a separate thread
                executorService.execute(() -> startKeyExchange());
            }

            @Override
            public void surfaceChanged(SurfaceHolder surfaceHolder, int i, int i1, int i2) {}

            @Override
            public void surfaceDestroyed(SurfaceHolder surfaceHolder) {
                if (socket != null && !socket.isClosed()) {
                    socket.close();
                }
            }
        });
    }

    private void startKeyExchange() {
        try {
            InetAddress serverAddr = InetAddress.getByName(serverAddress);
            socket = new DatagramSocket();

            // Send the shared key to the server (drone)
            DatagramPacket keyPacket = new DatagramPacket(sharedKey, sharedKey.length, serverAddr, port);
            socket.send(keyPacket);
            Log.i(TAG, "Shared key sent to server.");

            // Wait for server response (initial nonce)
            byte[] buffer = new byte[12];  // Buffer size matches nonce size (12 bytes)
            DatagramPacket responsePacket = new DatagramPacket(buffer, buffer.length);
            socket.setSoTimeout(20000); // Set timeout for 20 seconds to account for any delays

            boolean nonceReceived = false;
            int retries = 3;

            for (int i = 0; i < retries && !nonceReceived; i++) {
                try {
                    socket.receive(responsePacket);
                    byte[] responseData = Arrays.copyOf(responsePacket.getData(), responsePacket.getLength());
                    Log.i(TAG, "Received initial nonce from server: " + bytesToHex(responseData));
                    nonceReceived = true;
                    // Proceed to start video stream
                    startVideoStream();
                } catch (Exception e) {
                    Log.e(TAG, "Attempt " + (i + 1) + " - Timeout waiting for server response. No response received.", e);
                }
            }

            if (!nonceReceived) {
                Log.e(TAG, "Failed to receive initial nonce after " + retries + " attempts.");
            }

        } catch (Exception e) {
            Log.e(TAG, "Socket error occurred during key exchange: " + e.getMessage(), e);
        }
    }

    // Placeholder implementation for startVideoStream method
    private void startVideoStream() {
        //add 10 second delay
        try {
            Thread.sleep(10000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        try {
            byte[] receiveBuffer = new byte[MAX_PACKET_SIZE];

            while (true) {
                DatagramPacket videoPacket = new DatagramPacket(receiveBuffer, receiveBuffer.length);
                socket.receive(videoPacket);

                // Extract the packet data
                byte[] packetData = Arrays.copyOf(videoPacket.getData(), videoPacket.getLength());

                if (packetData.length < 16) {
                    Log.e(TAG, "Received packet is too small to contain valid data.");
                    continue;
                }
                int frameSize = FIXED_FRAME_SIZE;
                //frameSize = ((packetData[0] & 0xff) << 24) | ((packetData[1] & 0xff) << 16) |
                        //((packetData[2] & 0xff) << 8) | (packetData[3] & 0xff);

                // Updated condition to accurately validate the frame size
                if (frameSize <= 0 || frameSize > (packetData.length - 16)) {
                    Log.e(TAG, "Invalid frame size received: " + frameSize + ". Expected size within valid range.");
                    continue;
                }

                byte[] nonce = Arrays.copyOfRange(packetData, 4, 16);
                byte[] encryptedFrame = Arrays.copyOfRange(packetData, 16, packetData.length);

                try {
                    // Set up AES-GCM decryption
                    Cipher cipher = Cipher.getInstance(TRANSFORMATION);
                    GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
                    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(sharedKey, AES_ALGORITHM), spec);

                    // Decrypt the frame
                    byte[] decryptedFrame = cipher.doFinal(encryptedFrame);

                    if (decryptedFrame == null || decryptedFrame.length == 0) {
                        Log.e(TAG, "Decryption returned empty data.");
                        continue;
                    }

                    // Convert the decrypted frame to a Bitmap and display it
                    Bitmap bitmap = BitmapFactory.decodeByteArray(decryptedFrame, 0, decryptedFrame.length);
                    if (bitmap != null) {
                        runOnUiThread(() -> drawVideoFrame(bitmap));
                    } else {
                        Log.e(TAG, "Failed to decode bitmap from decrypted frame.");
                    }

                } catch (Exception e) {
                    Log.e(TAG, "Decryption failed: " + e.getMessage(), e);
                }
            }

        } catch (Exception e) {
            Log.e(TAG, "Error receiving or decrypting video stream: " + e.getMessage(), e);
        } finally {
            if (socket != null && !socket.isClosed()) {
                socket.close();
            }
            Log.i(TAG, "Socket closed.");
        }
    }

    private void drawVideoFrame(Bitmap bitmap) {
        SurfaceHolder holder = surfaceView.getHolder();
        if (holder.getSurface().isValid()) {
            Canvas canvas = holder.lockCanvas();
            if (canvas != null) {
                canvas.drawBitmap(bitmap, 0, 0, null);
                holder.unlockCanvasAndPost(canvas);
            } else {
                Log.e(TAG, "Failed to lock the canvas for drawing.");
            }
        } else {
            Log.e(TAG, "Surface is not valid for drawing.");
        }
    }

    // Utility function to convert bytes to a hexadecimal string
    private String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder(2 * bytes.length);
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
