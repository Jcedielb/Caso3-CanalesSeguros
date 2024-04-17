import javax.crypto.*;
import javax.crypto.spec.*;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate; 
import java.util.Base64;

public class SecurityUtils {
    // Métodos para cifrar y descifrar los datos
    public static String encrypt(String data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(new byte[16])); // IV ejemplo
        byte[] encrypted = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String decrypt(String encryptedData, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(new byte[16])); // IV ejemplo
        byte[] original = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
        return new String(original);
    }

    // Métodos adicionales para firma digital y verificación
    public static byte[] signData(byte[] data, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    public static boolean verifySignature(byte[] data, byte[] signatureBytes, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(signatureBytes);
    }

    // Métodos para generar y verificar HMAC
    public static String generateHMAC(String data, SecretKey key) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        byte[] hmacBytes = mac.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(hmacBytes);
    }

    public static boolean verifyHMAC(String data, String hmac, SecretKey key) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        byte[] hmacBytes = mac.doFinal(data.getBytes());
        byte[] decodedHmac = Base64.getDecoder().decode(hmac);
        return MessageDigest.isEqual(hmacBytes, decodedHmac);
    }
    
    

    public static KeyPair loadServerKeyPair(String keystorePath, String keystorePassword, String keyAlias) throws Exception {
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        try (InputStream in = new FileInputStream(keystorePath)) {
            keystore.load(in, keystorePassword.toCharArray());
        }

        Key key = keystore.getKey(keyAlias, keystorePassword.toCharArray());
        if (key instanceof PrivateKey) {
            // Certificado obtenido directamente, sin casting explícito
            Certificate cert = keystore.getCertificate(keyAlias);
            PublicKey publicKey = cert.getPublicKey();  // Debería trabajar sin necesidad de cast explícito
            PrivateKey privateKey = (PrivateKey) key;
            return new KeyPair(publicKey, privateKey);
        } else {
            throw new KeyStoreException("No private key found for alias: " + keyAlias);
        }
    }
}

