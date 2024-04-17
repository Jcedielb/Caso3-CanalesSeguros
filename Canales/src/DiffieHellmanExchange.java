import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.interfaces.*;
import javax.crypto.spec.*;

public class DiffieHellmanExchange {
    public static SecretKey simulateDiffieHellmanExchange() throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidParameterSpecException {
        // 1. Generar parámetros Diffie-Hellman
        AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
        paramGen.init(2048);  // Usar 2048 bits para la seguridad mejorada
        AlgorithmParameters params = paramGen.generateParameters();
        DHParameterSpec dhSpec = params.getParameterSpec(DHParameterSpec.class);

        // 2. Generar par de claves para cada participante
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
        keyPairGen.initialize(dhSpec);

        // Par de claves para el cliente
        KeyPair clientKeyPair = keyPairGen.generateKeyPair();
        // Par de claves para el servidor
        KeyPair serverKeyPair = keyPairGen.generateKeyPair();

        // 3. Establecimiento del acuerdo de claves
        KeyAgreement clientKeyAgree = KeyAgreement.getInstance("DH");
        clientKeyAgree.init(clientKeyPair.getPrivate());
        clientKeyAgree.doPhase(serverKeyPair.getPublic(), true);

        // 4. Generar la clave secreta
        byte[] clientSecret = clientKeyAgree.generateSecret();
        SecretKeySpec keySpec = new SecretKeySpec(clientSecret, 0, 16, "AES");  // Usar solo los primeros 128 bits (16 bytes)
        return keySpec;
    }
}
