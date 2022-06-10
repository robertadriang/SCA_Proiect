import com.google.gson.Gson;
import com.google.gson.JsonObject;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
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

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException, InvalidKeySpecException, SignatureException, InterruptedException {
        if (args.length==0){
            System.out.println("Merchant started dirrectly");
            Merchant m1 = new Merchant();
            m1.start(6666);
        }else{
            System.out.println("Merchant started at port:"+args[0]);
            Merchant m1 = new Merchant();
            m1.start(Integer.parseInt(args[0]));
        }

    }

    private void start(int port) throws IOException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidKeySpecException, SignatureException, InterruptedException {
        ServerSocket serverSocket = new ServerSocket(port);
        while (true) {
            Socket clientSocket = serverSocket.accept();
            // Generate keys
            createKeys();

            // Send public key to client and do the first step in the protocol (receive)
            var clientWrite = new PrintWriter(clientSocket.getOutputStream(), true);
            clientWrite.println(Base64.getEncoder().encodeToString(publicRsaKeyMerchant.getEncoded()));

            var clientRead = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            JsonObject clientToMerchant1Json = new Gson().fromJson(clientRead.readLine(), JsonObject.class);
            System.out.println("[STEP1] Encrypted JSON received from client:" + clientToMerchant1Json);
            clientToMerchant1Json = HybridCrypto.decrypt(clientToMerchant1Json, privateRsaKeyMerchant);
            System.out.println("[STEP1] Decrypted JSON received from client:" + clientToMerchant1Json);

            byte[] aesKeyArray = Base64.getDecoder().decode(clientToMerchant1Json.get("aesKey").getAsString());
            byte[] ivArray = Base64.getDecoder().decode(clientToMerchant1Json.get("iv").getAsString());
            Key aesKey = new SecretKeySpec(aesKeyArray, 0, aesKeyArray.length, "AES");
            IvParameterSpec iv = new IvParameterSpec(ivArray);

            PublicKey publicRsaKeyClient = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(clientToMerchant1Json.get("publicRsaKeyCustomer").getAsString())));

            // Send sid/sig(sid) to customer in the second step
            int sid = (int) Math.floor(Math.random() * (100 + 1));
            byte[] signature = Signer.sign(privateRsaKeyMerchant, sid);

            JsonObject merchantToClient2Json = new JsonObject();
            merchantToClient2Json.addProperty("sid", sid);
            merchantToClient2Json.addProperty("signature", Base64.getEncoder().encodeToString(signature));
            System.out.println("[STEP2] JSON to send to customer:" + merchantToClient2Json);
            merchantToClient2Json = HybridCrypto.encrypt(merchantToClient2Json, aesKey, iv, publicRsaKeyClient);
            System.out.println("[STEP2] Encrypted JSON to send to customer:" + merchantToClient2Json);
            clientWrite.println(merchantToClient2Json);

            /// Receive step3
            JsonObject clientToMerchant3Json = new Gson().fromJson(clientRead.readLine(), JsonObject.class);
            System.out.println("[STEP3] Encrypted JSON received from client:" + clientToMerchant3Json);
            clientToMerchant3Json = HybridCrypto.decrypt(clientToMerchant3Json, privateRsaKeyMerchant);
            System.out.println("[STEP3] Decrypted JSON received from client:" + clientToMerchant3Json);

            JsonObject poJson = new Gson().fromJson(clientToMerchant3Json.get("po").getAsString(), JsonObject.class);
            byte[] poSignature = Base64.getDecoder().decode(poJson.get("signature").getAsString());
            poJson.remove("signature");
            System.out.println(poJson.toString());
            PurchaseOrder po = new Gson().fromJson(poJson.toString(), PurchaseOrder.class);

            if (Signer.validateSignature(poSignature, publicRsaKeyClient, po.orderDesc, po.sid, po.amount, po.NC) == false) {
                System.out.println("[STEP3] PO signature is not valid");
                System.exit(-2);
            } else {
                System.out.println("[STEP3] PO signature is correct");
            }
            if (po.sid != sid) {
                System.out.println("[STEP3] SID was modified");
                System.exit(-3);
            }
            if (po.amount < 0) {
                System.out.println("[STEP3] Amount is not valid");
                System.exit(-4);
            }

            /// Key exchange between M and PG
            Socket paymentSocket = new Socket("localhost", 7777);
            PrintWriter paymentWrite = new PrintWriter(paymentSocket.getOutputStream(), true);

            paymentWrite.println("merchant");
            // Get payment public key
            BufferedReader paymentRead = new BufferedReader(new InputStreamReader(paymentSocket.getInputStream()));
            PublicKey publicRsaKeyPayment = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.
                    getDecoder().decode(paymentRead.readLine())));

            // Send merchant public key
            paymentWrite.println(Base64.getEncoder().encodeToString(publicRsaKeyMerchant.getEncoded()));

            //// Step 4
            JsonObject merchantToPayment4Json = new JsonObject();
            merchantToPayment4Json.addProperty("pm", clientToMerchant3Json.get("pm").getAsString());
            String publicRsaKeyCustomerStr = Base64.getEncoder().encodeToString(publicRsaKeyClient.getEncoded());
            byte[] mToP4Signature = Signer.sign(privateRsaKeyMerchant, sid, publicRsaKeyCustomerStr, po.amount);
            String mToP4SigString = Base64.getEncoder().encodeToString(mToP4Signature);
            merchantToPayment4Json.addProperty("signature", mToP4SigString);

            System.out.println("[STEP4] JSON to send to PaymentGateway:" + merchantToPayment4Json);
            HybridCrypto.encrypt(merchantToPayment4Json, aesKey, iv, publicRsaKeyPayment);
            System.out.println("[STEP4] Encrypted JSON to send to PaymentGateway:" + merchantToPayment4Json);

            paymentWrite.println(merchantToPayment4Json);

            /// Step 5
            JsonObject paymentToMerchant5Json = new Gson().fromJson(paymentRead.readLine(), JsonObject.class);
            System.out.println("[STEP5] Encrypted JSON received from payment:" + paymentToMerchant5Json);
            paymentToMerchant5Json = HybridCrypto.decrypt(paymentToMerchant5Json, privateRsaKeyMerchant);
            System.out.println("[STEP5] Decrypted JSON received from payment:" + paymentToMerchant5Json);

            byte[] paymentSignature = Base64.getDecoder().decode(paymentToMerchant5Json.get("signature").getAsString());
            if (Signer.validateSignature(paymentSignature, publicRsaKeyPayment, paymentToMerchant5Json.get("response").getAsString(),
                    paymentToMerchant5Json.get("sid").getAsInt(), po.amount, po.NC) == false) {
                System.out.println("[STEP5] Gateway signature is not valid");
                System.exit(-6);
            } else {
                System.out.println("[STEP5] Gateway signature is valid");
            }

            /// Step 6
            System.out.println("[STEP6] JSON to send to client:" + paymentToMerchant5Json);
            JsonObject merchantToClient6Json = HybridCrypto.encrypt(paymentToMerchant5Json, aesKey, iv, publicRsaKeyClient);
            System.out.println("[STEP6] Encrypted JSON to send to client:" + merchantToClient6Json);

            //Thread.sleep(10_000);
            clientWrite.println(merchantToClient6Json);

        }


    }
}
