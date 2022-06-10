import com.google.gson.Gson;
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
import java.net.SocketTimeoutException;
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

        byte[] ivArray = new byte[16];
        new SecureRandom().nextBytes(ivArray);
        iv = new IvParameterSpec(ivArray);

        // Generate RSA pair
        KeyPairGenerator rsaKeyGen = KeyPairGenerator.getInstance("RSA");
        rsaKeyGen.initialize(2048);
        KeyPair keyPair = rsaKeyGen.generateKeyPair();
        publicRsaKeyCustomer = keyPair.getPublic();
        privateRsaKeyCustomer = keyPair.getPrivate();
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException, SignatureException {
        int port;
        if (args.length == 0) {
            System.out.println("Customer started dirrectly at port 6666");
            port = 6666;
        } else {
            System.out.println("Customer started at port:" + args[0]);
            port=Integer.parseInt(args[0]);
        }


        Customer c1 = new Customer();
        c1.createKeys();
        ///

        /// Retrieve public key from merchant and do the first step in the protocol (send)
        JsonObject clientToMerchant1 = new JsonObject();
        clientToMerchant1.addProperty("publicRsaKeyCustomer", Base64.getEncoder().encodeToString(c1.publicRsaKeyCustomer.getEncoded()));
        System.out.println("[STEP1] JSON to send to merchant:" + clientToMerchant1);

        Socket merchantSocket = new Socket("localhost", port);
        merchantSocket.setSoTimeout(3_000);
        var merchantRead = new BufferedReader(new InputStreamReader(merchantSocket.getInputStream()));
        PublicKey publicRsaKeyMerchant = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(merchantRead.readLine())));

        clientToMerchant1 = HybridCrypto.encrypt(clientToMerchant1, c1.aesKey, c1.iv, publicRsaKeyMerchant);
        System.out.println("[STEP1] Encrypted JSON to send to merchant:" + clientToMerchant1);
        var merchantWrite = new PrintWriter(merchantSocket.getOutputStream(), true);
        merchantWrite.println(clientToMerchant1);


        // Receive sid/sig(sid) from merchant in the second step
        JsonObject merchantToClient2Json = new Gson().fromJson(merchantRead.readLine(), JsonObject.class);
        System.out.println("[STEP2] Encrypted JSON received from merchant:" + merchantToClient2Json);
        merchantToClient2Json = HybridCrypto.decrypt(merchantToClient2Json, c1.privateRsaKeyCustomer);
        System.out.println("[STEP2] Decrypted JSON received from merchant:" + merchantToClient2Json);

        /// Check the sid signature
        int sid = Integer.parseInt(merchantToClient2Json.get("sid").getAsString());
        byte[] sidSignature = Base64.getDecoder().decode(merchantToClient2Json.get("signature").getAsString());
        if (!Signer.validateSignature(sidSignature, publicRsaKeyMerchant, sid)) {
            System.out.println("[STEP2] Sid signature is invalid");
            System.exit(-1);
        }
        System.out.println("[STEP2] Sid signature is correct");


        //// Step 3
        Socket paymentSocket = new Socket("localhost", 7777);
        PrintWriter paymentWrite = new PrintWriter(paymentSocket.getOutputStream(), true);
        paymentWrite.println("customer");

        BufferedReader paymentRead = new BufferedReader(new InputStreamReader(paymentSocket.getInputStream()));
        PublicKey publicRsaKeyPayment = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.
                getDecoder().decode(paymentRead.readLine())));
        System.out.println("[STEP3] Received public key from PaymentGateway");

        // Construct PM (PI+sig(PI))
        int nonce = (int) Math.floor(Math.random() * (100 + 1));
        int merchantId = port-6666;  /// TODO AI GRIJA SA SCHIMBI
        float amount = 525.75f;
        String publicRsaKeyCustomerStr = Base64.getEncoder().encodeToString(c1.publicRsaKeyCustomer.getEncoded());
        PaymentInfo pi = new PaymentInfo("4111 1111 1111 1111", "11/22", "123456", sid,
                amount, publicRsaKeyCustomerStr, nonce, merchantId);
        byte[] piSignature = Signer.sign(c1.privateRsaKeyCustomer, pi.cardN, pi.cardExp,
                pi.cCode, pi.sid, pi.amount, pi.publicRsaKeyCustomer, pi.NC,
                pi.mId);

        /// https://memorynotfound.com/gson-tree-model-write-and-parse-to-and-from-json/
        JsonObject pmJson = new Gson().toJsonTree(pi, PaymentInfo.class).getAsJsonObject();
        String piSigString = Base64.getEncoder().encodeToString(piSignature);
        pmJson.addProperty("signature", piSigString);
        pmJson = HybridCrypto.encrypt(pmJson, c1.aesKey, c1.iv, publicRsaKeyPayment);

        // Construct PO
        PurchaseOrder po = new PurchaseOrder("This is a test order", sid, amount, nonce);
        byte[] poSignature = Signer.sign(c1.privateRsaKeyCustomer, po.orderDesc, po.sid, po.amount, po.NC);
        JsonObject poJson = new Gson().toJsonTree(po, PurchaseOrder.class).getAsJsonObject();
        poJson.addProperty("signature", Base64.getEncoder().encodeToString(poSignature));

        /// Construct {PM,PO}
        JsonObject clientToMerchant3Json = new JsonObject();

        //// Send step3
        clientToMerchant3Json.addProperty("pm", pmJson.toString());
        clientToMerchant3Json.addProperty("po", poJson.toString());
        System.out.println("[STEP3] JSON to send to merchant:" + clientToMerchant3Json);
        clientToMerchant3Json = HybridCrypto.encrypt(clientToMerchant3Json, c1.aesKey, c1.iv, publicRsaKeyMerchant);
        System.out.println("[STEP3] Encrypted JSON to send to merchant:" + clientToMerchant1);
        merchantWrite.println(clientToMerchant3Json);

        try {
            JsonObject merchantToClient6Json = new Gson().fromJson(merchantRead.readLine(), JsonObject.class);
            System.out.println("[STEP6] Encrypted JSON received from merchant:" + merchantToClient6Json);
            merchantToClient6Json = HybridCrypto.decrypt(merchantToClient6Json, c1.privateRsaKeyCustomer);
            System.out.println("[STEP6] Decrypted JSON received from merchant:" + merchantToClient6Json);

            byte[] pgSignature = Base64.getDecoder().decode(merchantToClient6Json.get("signature").getAsString());
            if (!Signer.validateSignature(pgSignature, publicRsaKeyPayment, merchantToClient6Json.get("response").getAsString(), sid, po.amount, po.NC)) {
                System.out.println("[STEP6] Payment signature is not valid");
                System.exit(-8);
            } else {
                System.out.println("[STEP6] Signature is valid");
            }
            if (sid != merchantToClient6Json.get("sid").getAsInt()) {
                System.out.println("[STEP6] SID is invalid!");
                System.exit(-9);
            }
            if (merchantToClient6Json.get("response").getAsString().equals("Ok")) {
                System.out.println("[STEP6] SUCCESSFUL TRANSACTION!");
            } else {
                System.out.println("[STEP6] INVALID RESPONSE!!!");
                System.exit(-10);
            }


        } catch (SocketTimeoutException e) {
            System.out.println("[STEP6] Merchant TIMEOUT");

            /// Step 7
            JsonObject clientToPayment7Json = new JsonObject();
            clientToPayment7Json.addProperty("sid", sid);
            clientToPayment7Json.addProperty("amount", po.amount);
            clientToPayment7Json.addProperty("NC", po.NC);
            String publicRsaKeyCustomerString = Base64.getEncoder().encodeToString(c1.publicRsaKeyCustomer.getEncoded());
            clientToPayment7Json.addProperty("publicRsaKeyCustomer", publicRsaKeyCustomerString);
            byte[] clientSignature = Signer.sign(c1.privateRsaKeyCustomer, sid, po.amount, po.NC, publicRsaKeyCustomerString);
            clientToPayment7Json.addProperty("signature", Base64.getEncoder().encodeToString(clientSignature));

            System.out.println("[STEP7] JSON to send to payment:" + clientToPayment7Json);
            clientToPayment7Json = HybridCrypto.encrypt(clientToPayment7Json, c1.aesKey, c1.iv, publicRsaKeyPayment);
            System.out.println("[STEP7] Encrypted JSON to send to payment:" + clientToPayment7Json);
            paymentWrite.println(clientToPayment7Json);


            JsonObject paymentToClient8Json = new Gson().fromJson(paymentRead.readLine(), JsonObject.class);
            System.out.println("[STEP8] Encrypted JSON received from Payment:" + paymentToClient8Json);
            paymentToClient8Json = HybridCrypto.decrypt(paymentToClient8Json, c1.privateRsaKeyCustomer);
            System.out.println("[STEP8] Decrypted JSON received from Payment:" + paymentToClient8Json);


            byte[] pgSignature = Base64.getDecoder().decode(paymentToClient8Json.get("signature").getAsString());
            if (!Signer.validateSignature(pgSignature, publicRsaKeyPayment, paymentToClient8Json.get("response").getAsString(), sid, po.amount, po.NC)) {
                System.out.println("[STEP8] Payment signature is not valid");
                System.exit(-11);
            } else {
                System.out.println("[STEP8] Signature is valid");
            }
            if (sid != paymentToClient8Json.get("sid").getAsInt()) {
                System.out.println("[STEP8] SID is invalid!");
                System.exit(-12);
            }
            if (paymentToClient8Json.get("response").getAsString().equals("Ok")) {
                System.out.println("[STEP8] SUCCESSFUL TRANSACTION!");
            } else {
                System.out.println("[STEP8] INVALID RESPONSE!!!");
                System.exit(-13);
            }

        }

    }
}
