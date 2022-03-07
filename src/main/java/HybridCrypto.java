import com.google.gson.JsonObject;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Base64;

// https://www.baeldung.com/java-aes-encryption-decryption
// https://www.baeldung.com/java-rsa
public class HybridCrypto {
    public static JsonObject encrypt(JsonObject toEncrypt, Key aesKey, IvParameterSpec iv, PublicKey publicRsaKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aes.init(Cipher.ENCRYPT_MODE, aesKey, iv);

        // Encrypt each value of the JSON using AES
        for(String key:toEncrypt.keySet()){
            String value;
            if (!toEncrypt.get(key).getAsJsonPrimitive().isString())
                value = toEncrypt.get(key).toString();
            else
                value = toEncrypt.get(key).getAsString();
            byte[] encryptedValue = aes.doFinal(value.getBytes());
            toEncrypt.addProperty(key, Base64.getEncoder().encodeToString(encryptedValue));
        }

        // Encrypt the AES key used using RSA
        Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsa.init(Cipher.ENCRYPT_MODE, publicRsaKey);
        byte[] encAesKey = rsa.doFinal(aesKey.getEncoded());
        byte[] encIv = rsa.doFinal(iv.getIV());
        toEncrypt.addProperty("aesKey", Base64.getEncoder().encodeToString(encAesKey));
        toEncrypt.addProperty("iv", Base64.getEncoder().encodeToString(encIv));
        return toEncrypt;
    }

    public static JsonObject decrypt(JsonObject toDecrypt, PrivateKey privateRsaKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        // Decrypt the AES key using RSA
        Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsa.init(Cipher.DECRYPT_MODE, privateRsaKey);
        byte[] decAesKey = rsa.doFinal(Base64.getDecoder().decode(toDecrypt.get("aesKey").getAsString()));
        byte[] decIv = rsa.doFinal(Base64.getDecoder().decode(toDecrypt.get("iv").getAsString()));

        // Decrypt each value of the JSON using AES
        Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(decAesKey, 0, decAesKey.length, "AES"),
                new IvParameterSpec(decIv));

        for (String key : toDecrypt.keySet())
        {
            if (key.equals("aesKey") || key.equals("iv"))
                continue;
            byte[] decryptedValue = aes.doFinal(Base64.getDecoder().decode(toDecrypt.get(key).getAsString()));
            toDecrypt.addProperty(key, new String(decryptedValue));
        }

        toDecrypt.addProperty("aesKey", Base64.getEncoder().encodeToString(decAesKey));
        toDecrypt.addProperty("iv", Base64.getEncoder().encodeToString(decIv));
        return toDecrypt;
    }
}
