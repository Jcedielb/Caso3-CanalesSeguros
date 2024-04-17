import javax.crypto.*;
import javax.crypto.spec.*;

import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

import java.security.spec.KeySpec;


public class SecurityUtils {
    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String KEY_FACTORY_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int KEY_SIZE = 256; // AES key size
    private static final int ITERATION_COUNT = 65536;
    private static final int IV_SIZE = 16;

    public static SecretKey deriveKeyFromPassword(char[] password, byte[] salt) throws GeneralSecurityException {
        KeySpec spec = new PBEKeySpec(password, salt, ITERATION_COUNT, KEY_SIZE);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256"); // Correct algorithm
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }
    

    public static String encrypt(String data, SecretKey key) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv); // Securely generate a new IV
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] encrypted = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
        byte[] combined = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);
        return Base64.getEncoder().encodeToString(combined);
    }

    public static String decrypt(String encryptedDataWithIv, SecretKey key) throws GeneralSecurityException {
        byte[] decoded = Base64.getDecoder().decode(encryptedDataWithIv);
        byte[] iv = Arrays.copyOfRange(decoded, 0, IV_SIZE);
        byte[] encryptedData = Arrays.copyOfRange(decoded, IV_SIZE, decoded.length);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] decrypted = cipher.doFinal(encryptedData);
        return new String(decrypted, StandardCharsets.UTF_8);
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
        byte[] hmacBytes = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hmacBytes);
    }

    public static boolean verifyHMAC(String data, String hmac, SecretKey key) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);
        byte[] hmacBytes = mac.doFinal(dataBytes);
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
            Certificate cert = keystore.getCertificate(keyAlias);
            PublicKey publicKey = cert.getPublicKey();
            PrivateKey privateKey = (PrivateKey) key;
            return new KeyPair(publicKey, privateKey);
        } else {
            throw new KeyStoreException("No private key found for alias: " + keyAlias);
        }
    }
        public static void main(String[] args) {
        try {
            String password = "your_password_here";
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);

            SecretKey key = deriveKeyFromPassword(password.toCharArray(), salt);
            System.out.println("Key generated successfully.");
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
    }
}
