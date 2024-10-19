package com.shafiq.nsrg;

import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Canvas;
import android.os.Bundle;
import android.view.SurfaceHolder;
import android.view.SurfaceView;

import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import java.io.ByteArrayInputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.nio.ByteBuffer;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

// Add the following code to handle the third screen where the video from the drone is displayed

public class VideoStreamActivity extends AppCompatActivity {

    private static final int MAX_PACKET_SIZE = 65535;  // Maximum UDP packet size
    private static final String AES_ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;  // 16 bytes = 128 bits
    private static final int NONCE_LENGTH = 12;  // 12 bytes for GCM nonce

    private SurfaceView videoSurfaceView;
    private SurfaceHolder surfaceHolder;
    private String sharedKeyHex;
    private String serverAddress;
    private int port;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_video_stream);

        // Initialize the SurfaceView to display the video
        videoSurfaceView = findViewById(R.id.videoSurfaceView);
        surfaceHolder = videoSurfaceView.getHolder();

        // Get shared key and server address from intent
        Intent intent = getIntent();
        sharedKeyHex = intent.getStringExtra("sharedKey");
        serverAddress = intent.getStringExtra("serverAddress");
        port = intent.getIntExtra("port", 22222);

        // Start the video streaming thread
        new Thread(this::startVideoStream).start();
    }

    private void startVideoStream() {
        try (DatagramSocket socket = new DatagramSocket(port)) {
            System.out.println("Waiting for packets...");

            // Convert shared key from hex string to bytes
            byte[] sharedKeyBytes = hexStringToByteArray(sharedKeyHex);

            // Receive the single session nonce (12 bytes)
            byte[] nonceBuffer = new byte[NONCE_LENGTH];
            DatagramPacket noncePacket = new DatagramPacket(nonceBuffer, nonceBuffer.length);
            socket.receive(noncePacket);
            byte[] nonce = noncePacket.getData();

            while (true) {
                // Receive the packet
                byte[] receiveBuffer = new byte[MAX_PACKET_SIZE];
                DatagramPacket packet = new DatagramPacket(receiveBuffer, receiveBuffer.length);
                socket.receive(packet);

                // Extract frame size
                ByteBuffer buffer = ByteBuffer.wrap(packet.getData());
                int frameSize = buffer.getInt();  // Frame size

                // Read the encrypted frame and tag
                byte[] encryptedFrameWithTag = new byte[frameSize];
                buffer.get(encryptedFrameWithTag);

                try {
                    // Set up AES-GCM decryption using the single session nonce
                    Cipher cipher = Cipher.getInstance(TRANSFORMATION);
                    GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
                    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(sharedKeyBytes, AES_ALGORITHM), spec);

                    // Decrypt the frame
                    byte[] decryptedFrame = cipher.doFinal(encryptedFrameWithTag);

                    // Convert the decrypted frame to a Bitmap and display
                    ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(decryptedFrame);
                    Bitmap bitmap = BitmapFactory.decodeStream(byteArrayInputStream);

                    if (bitmap != null) {
                        runOnUiThread(() -> drawVideoFrame(bitmap));
                    }

                } catch (Exception e) {
                    System.out.println("Decryption failed: " + e.getMessage());
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void drawVideoFrame(Bitmap bitmap) {
        Canvas canvas = surfaceHolder.lockCanvas();
        if (canvas != null) {
            canvas.drawBitmap(bitmap, 0, 0, null);
            surfaceHolder.unlockCanvasAndPost(canvas);
        }
    }

    // Helper method to convert hex string to byte array
    private byte[] hexStringToByteArray(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}
