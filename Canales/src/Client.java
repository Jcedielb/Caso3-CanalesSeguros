import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.*;
import javax.crypto.spec.*;

public class Client {
    private static final String SERVER_HOST = "localhost";
    private static final int SERVER_PORT = 12345;
    private SecretKey sessionKey; // Llave de sesión derivada del intercambio Diffie-Hellman

    public void startClient() throws Exception {
        try (Socket socket = new Socket(SERVER_HOST, SERVER_PORT);
             DataOutputStream output = new DataOutputStream(socket.getOutputStream());
             DataInputStream input = new DataInputStream(socket.getInputStream())) {
            
            // Iniciar protocolo de comunicación segura
            initiateSecureCommunication(output, input);

            // Envío de una consulta cifrada
            performQuery(output, input);

        } catch (IOException e) {
            System.err.println("Failed to communicate with the server: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void initiateSecureCommunication(DataOutputStream output, DataInputStream input) throws IOException, GeneralSecurityException {
        output.writeUTF("SECURE INIT");
        String serverResponse = input.readUTF();
        if (!"SECURE ACK".equals(serverResponse)) {
            throw new IOException("Secure connection establishment failed: " + serverResponse);
        }

        // Simular el intercambio de claves Diffie-Hellman y establecer sessionKey
        sessionKey = simulateDiffieHellmanExchange();
    }

    private void performQuery(DataOutputStream output, DataInputStream input) throws Exception {
        String query = "consulta";
        String encryptedQuery = SecurityUtils.encrypt(query, sessionKey);
        output.writeUTF(encryptedQuery);

        // Recepción y descifrado de la respuesta
        String encryptedResponse = input.readUTF();
        String response = SecurityUtils.decrypt(encryptedResponse, sessionKey);
        System.out.println("Respuesta del servidor: " + response);
    }

    private SecretKey simulateDiffieHellmanExchange() throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidParameterSpecException, InvalidKeySpecException {
        return DiffieHellmanExchange.simulateDiffieHellmanExchange();
    }

    public static void main(String[] args) {
        try {
            new Client().startClient();
        } catch (Exception e) {
            System.err.println("Error starting client: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
