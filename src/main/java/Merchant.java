import com.google.gson.Gson;
import com.google.gson.JsonObject;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.util.Base64;

public class Merchant {
    public PublicKey publicRsaKeyMerchant;
    private PrivateKey privateRsaKeyMerchant;

    public void createKeys() throws NoSuchAlgorithmException {
        KeyPairGenerator rsaKeyGen = KeyPairGenerator.getInstance("RSA");
        rsaKeyGen.initialize(2048);
        KeyPair keyPair = rsaKeyGen.generateKeyPair();

        publicRsaKeyMerchant = keyPair.getPublic();
        privateRsaKeyMerchant = keyPair.getPrivate();
    }
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException {
        Merchant m1 = new Merchant();
        m1.start(6666);
    }

    private void start(int port) throws IOException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        ServerSocket serverSocket = new ServerSocket(port);
        Socket clientSocket = serverSocket.accept();

        // Generate keys
        createKeys();

        // Send public key to client and do the first step in the protocol (receive)
        var clientWrite = new PrintWriter(clientSocket.getOutputStream(), true);
        clientWrite.println(Base64.getEncoder().encodeToString(publicRsaKeyMerchant.getEncoded()));

        var clientRead = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        JsonObject clientToMerchant1Json = new Gson().fromJson(clientRead.readLine(),JsonObject.class);
        System.out.println("[STEP1] Encrypted JSON received from client:"+clientToMerchant1Json);
        clientToMerchant1Json=HybridCrypto.decrypt(clientToMerchant1Json,privateRsaKeyMerchant);
        System.out.println("[STEP1] Decrypted JSON received from client:"+clientToMerchant1Json);
    }
}
