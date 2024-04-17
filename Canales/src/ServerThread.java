import java.io.*;
import java.net.*;
import java.security.KeyPair;
import javax.crypto.SecretKey;

public class ServerThread extends Thread {
    private Socket socket;
    private KeyPair serverKeyPair;
    private SecretKey sessionKey; // Esta llave se generará durante el intercambio Diffie-Hellman

    public ServerThread(Socket socket, KeyPair keyPair) {
        this.socket = socket;
        this.serverKeyPair = keyPair;
    }

    public void run() {
        try (DataInputStream input = new DataInputStream(socket.getInputStream());
             DataOutputStream output = new DataOutputStream(socket.getOutputStream())) {
            
            // Inicialización segura
            boolean secureInitDone = false;
            while (!secureInitDone) {
                try {
                    String clientMessage = input.readUTF();
                    if ("SECURE INIT".equals(clientMessage)) {
                        output.writeUTF("SECURE ACK");
                        secureInitDone = true;  // Confirmar que la inicialización segura se ha completado
                    } else {
                        output.writeUTF("ERROR: Secure initialization failed");
                        return;  // Salir si la inicialización segura falla
                    }
                } catch (EOFException eof) {
                    System.out.println("Client has closed the connection during initialization.");
                    return;
                }
            }

            // Procesamiento de mensajes después de una inicialización segura
            if (secureInitDone) {
                boolean active = true;
                while (active) {
                    try {
                        String encryptedMessage = input.readUTF();
                        String plainText = SecurityUtils.decrypt(encryptedMessage, sessionKey);
                        String response = "RESPONSE"; // La lógica de negocio determinaría la respuesta real
                        String encryptedResponse = SecurityUtils.encrypt(response, sessionKey);
                        output.writeUTF(encryptedResponse);
                    } catch (EOFException eof) {
                        System.out.println("Client has closed the connection.");
                        active = false;  // Finalizar el bucle si el cliente se desconecta
                    } catch (IOException ex) {
                        System.err.println("IO exception: " + ex.getMessage());
                        active = false;  // Manejar otras excepciones de I/O
                    } catch (Exception e) {
                        // TODO Auto-generated catch block
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
