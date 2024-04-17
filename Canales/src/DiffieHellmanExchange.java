import java.security.*;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.*;
import javax.crypto.interfaces.*;
import javax.crypto.spec.*;

public class DiffieHellmanExchange {
    public static SecretKey simulateDiffieHellmanExchange() throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidParameterSpecException {
        // 1. Generar parámetros Diffie-Hellman
        AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
        paramGen.init(1024);  // Tamaño de la llave de 1024 bits
        AlgorithmParameters params = paramGen.generateParameters();
        DHParameterSpec dhSpec = params.getParameterSpec(DHParameterSpec.class);

        // 2. Generar par de claves para cada participante (simulando ambos lados en este ejemplo)
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
        keyPairGen.initialize(dhSpec);

        // Par de claves para el "cliente"
        KeyPair clientKeyPair = keyPairGen.generateKeyPair();

        // Par de claves para el "servidor"
        KeyPair serverKeyPair = keyPairGen.generateKeyPair();

        // 3. Realizar el intercambio de claves
        KeyAgreement clientKeyAgree = KeyAgreement.getInstance("DH");
        clientKeyAgree.init(clientKeyPair.getPrivate());

        KeyAgreement serverKeyAgree = KeyAgreement.getInstance("DH");
        serverKeyAgree.init(serverKeyPair.getPrivate());

        // 4. Con la clave pública del otro participante
        clientKeyAgree.doPhase(serverKeyPair.getPublic(), true);
        serverKeyAgree.doPhase(clientKeyPair.getPublic(), true);

        // 5. Generar la clave secreta compartida
        SecretKey clientSecretKey = clientKeyAgree.generateSecret("AES");
        SecretKey serverSecretKey = serverKeyAgree.generateSecret("AES");

        // Asumiendo que las claves generadas son iguales, retornamos una de ellas
        return clientSecretKey;  // O serverSecretKey, ambos deberían ser iguales
    }
}
