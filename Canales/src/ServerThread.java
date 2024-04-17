import java.io.*;
import java.net.*;
import java.security.KeyPair;
import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;

public class ServerThread extends Thread {
    private Socket socket;
    private KeyPair serverKeyPair;
    private SecretKey sessionKey; // This key will be generated during Diffie-Hellman exchange or mocked for simulation

    public ServerThread(Socket socket, KeyPair keyPair) {
        this.socket = socket;
        this.serverKeyPair = keyPair;
        initializeSessionKey(); // Initialize session key
    }

    private void initializeSessionKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256); // For AES-256
            this.sessionKey = keyGen.generateKey();
            if (this.sessionKey == null) {
                System.out.println("Session key generation failed.");
            } else {
                System.out.println("Session key successfully generated.");
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("Failed to generate session key");
        }
    }
    

    public void run() {
        try (DataInputStream input = new DataInputStream(socket.getInputStream());
             DataOutputStream output = new DataOutputStream(socket.getOutputStream())) {
            
            // Secure initialization
            boolean secureInitDone = false;
            while (!secureInitDone) {
                try {
                    String clientMessage = input.readUTF();
                    if ("SECURE INIT".equals(clientMessage)) {
                        output.writeUTF("SECURE ACK");
                        secureInitDone = true;  // Confirm secure initialization has completed
                    } else {
                        output.writeUTF("ERROR: Secure initialization failed");
                        return;  // Exit if secure initialization fails
                    }
                } catch (EOFException eof) {
                    System.out.println("Client has closed the connection during initialization.");
                    return;
                }
            }

            // Message processing after secure initialization
            if (secureInitDone) {
                boolean active = true;
                while (active) {
                    try {
                        String encryptedMessage = input.readUTF();
                        if (sessionKey == null) {
                            System.out.println("Session key is null before decryption.");
                        } else {
                            System.out.println("Session key is available for decryption.");
                        }
                        String plainText = SecurityUtils.decrypt(encryptedMessage, sessionKey);
                        String response = "RESPONSE"; // Business logic would determine the actual response
                        String encryptedResponse = SecurityUtils.encrypt(response, sessionKey);
                        output.writeUTF(encryptedResponse);
                    } catch (EOFException eof) {
                        System.out.println("Client has closed the connection.");
                        active = false;  // End loop if client disconnects
                    } catch (IOException ex) {
                        System.err.println("IO exception: " + ex.getMessage());
                        active = false;  // Handle other I/O exceptions
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }

        } catch (IOException e) {
            System.err.println("Server Thread I/O error: " + e.getMessage());
        } finally {
            try {
                if (socket != null) {
                    socket.close();
                }
            } catch (IOException e) {
                System.err.println("Error closing socket: " + e.getMessage());
            }
        }
    }
}
