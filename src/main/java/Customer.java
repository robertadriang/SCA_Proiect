import com.google.gson.JsonObject;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Customer {
    public Key aesKey;
    public IvParameterSpec iv;

    public PublicKey publicRsaKeyCustomer;
    private PrivateKey privateRsaKeyCustomer;

    // https://www.baeldung.com/java-aes-encryption-decryption
    // https://www.baeldung.com/java-rsa
    public void createKeys() throws NoSuchAlgorithmException {
        // Generate AES key + IV parameter
        KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES");
        aesKeyGen.init(128);
        aesKey = aesKeyGen.generateKey();

        byte[] iv_array = new byte[16];
        new SecureRandom().nextBytes(iv_array);
        iv = new IvParameterSpec(iv_array);

        // Generate RSA pair
        KeyPairGenerator rsaKeyGen = KeyPairGenerator.getInstance("RSA");
        rsaKeyGen.initialize(2048);
        KeyPair keyPair = rsaKeyGen.generateKeyPair();
        publicRsaKeyCustomer = keyPair.getPublic();
        privateRsaKeyCustomer = keyPair.getPrivate();
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException {
        Customer c1 = new Customer();
        c1.createKeys();

        /// Retrieve public key from merchant and do the first step in the protocol (send)
        JsonObject clientToMerchant1 = new JsonObject();
        clientToMerchant1.addProperty("publicRsaKeyCustomer", Base64.getEncoder().encodeToString(c1.publicRsaKeyCustomer.getEncoded()));
        System.out.println("[STEP1] Json to send to customer:" + clientToMerchant1);

        Socket merchantSocket = new Socket("localhost", 6666);
        var merchantRead = new BufferedReader(new InputStreamReader(merchantSocket.getInputStream()));
        PublicKey publicRsaKeyMerchant = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(merchantRead.readLine())));

        clientToMerchant1 = HybridCrypto.encrypt(clientToMerchant1, c1.aesKey, c1.iv, publicRsaKeyMerchant);
        System.out.println("[STEP1] Encrypted Json to send to customer:" + clientToMerchant1);
        var merchantWrite = new PrintWriter(merchantSocket.getOutputStream(), true);
        merchantWrite.println(clientToMerchant1);

    }
}
