import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;

public class Server {
    private static final int PORT = 12345;

    public static void main(String[] args) {
        try {
            ServerSocket serverSocket = new ServerSocket(PORT);
            System.out.println("Server started on port " + PORT);

            // Los parámetros de la ruta al keystore, la contraseña y el alias
            String keystorePath = "keystore.jks";
            String keystorePassword = "cedielb13";
            String keyAlias = "serverkey";

            // Llama al método con los parámetros correctos
            KeyPair keyPair = SecurityUtils.loadServerKeyPair(keystorePath, keystorePassword, keyAlias);

            while (true) {
                Socket clientSocket = serverSocket.accept();
                new ServerThread(clientSocket, keyPair).start();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
