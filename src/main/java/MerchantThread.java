import com.google.gson.Gson;
import com.google.gson.JsonObject;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class MerchantThread extends Thread {
    public PublicKey publicRsaKeyPayment;
    private PrivateKey privateRsaKeyPayment;
    private BufferedReader readMerchant;
    private PrintWriter writeMerchant;
    private Socket socket;

    public MerchantThread(PublicKey publicRsaKeyPayment, PrivateKey privateRsaKeyPayment, BufferedReader readMerchant, Socket socket) throws IOException {
        this.publicRsaKeyPayment = publicRsaKeyPayment;
        this.privateRsaKeyPayment = privateRsaKeyPayment;
        this.readMerchant = readMerchant;
        this.writeMerchant = new PrintWriter(socket.getOutputStream(), true);
        ;
        this.socket = socket;
    }

    public void run() {
        System.out.println("Entering merchant thread");
        System.out.println("Sending public key to merchant");
        /// Send public key to merchent
        writeMerchant.println(Base64.getEncoder().encodeToString(publicRsaKeyPayment.getEncoded()));

        try {
            /// Receive public key from merchant
            PublicKey publicRsaKeyMerchant = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(readMerchant.readLine())));

            /// Step 4 receive from merchant
            JsonObject merchantToPayment4Json = new Gson().fromJson(readMerchant.readLine(), JsonObject.class);
            System.out.println("[STEP4] Encrypted JSON received from merchant:" + merchantToPayment4Json);
            merchantToPayment4Json = HybridCrypto.decrypt(merchantToPayment4Json, privateRsaKeyPayment);
            System.out.println("[STEP4] Decrypted JSON received from merchant:" + merchantToPayment4Json);
            JsonObject pm = new Gson().fromJson(merchantToPayment4Json.get("pm").getAsString(), JsonObject.class);
            pm = HybridCrypto.decrypt(pm, privateRsaKeyPayment);
            System.out.println("[STEP4] Decrypted PM received from merchant:" + pm);

            //// Move PI after remove if it won't work
            PaymentInfo pi = new Gson().fromJson(pm.toString(), PaymentInfo.class);
            byte[] piSignature = Base64.getDecoder().decode(pm.get("signature").getAsString().getBytes());
            //pm.remove("signature");
            PublicKey publicRsaKeyClient = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(pi.publicRsaKeyCustomer)));

            if (Signer.validateSignature(piSignature, publicRsaKeyClient, pi.cardN, pi.cardExp, pi.cCode, pi.sid, pi.amount, pi.publicRsaKeyCustomer, pi.NC, pi.mId) == false) {
                System.out.println("[STEP4] Client signature is not valid");
                System.exit(-5);
            }

            byte[] mSignature = Base64.getDecoder().decode(merchantToPayment4Json.get("signature").getAsString().getBytes());
            if (Signer.validateSignature(mSignature, publicRsaKeyMerchant, pi.sid, pi.publicRsaKeyCustomer, pi.amount) == false) {
                System.out.println("[STEP4] Merchant signature is not valid");
                System.exit(-6);
            }

            /// TODO ADD CARD CHECKS HERE

            ///// Check by mId at the moment
            /// if mId is 1 simulate timeout/bad response
            boolean all_valid=true;
            if (pi.mId==1){
                all_valid=false;
                Thread.sleep(10_000);
            }

            String response;
            if (all_valid){
                System.out.println("[STEP4] All information is valid");
                response="Ok";
            }else{
                System.out.println("[STEP4] Information is not valid");
                response="NotOk";
            }
            /// Step 5
            JsonObject paymentToMerchant5Json= new JsonObject();
            paymentToMerchant5Json.addProperty("response",response);
            paymentToMerchant5Json.addProperty("sid",pi.sid);
            byte[] paymentSignature=Signer.sign(privateRsaKeyPayment,response,pi.sid,pi.amount,pi.NC);
            paymentToMerchant5Json.addProperty("signature",Base64.getEncoder().encodeToString(paymentSignature));

            // Extract AES key used for encryption
            System.out.println("JSON TO EXTRACT AES:"+merchantToPayment4Json);
            byte[] aesKeyArray = Base64.getDecoder().decode(merchantToPayment4Json.get("aesKey").getAsString());
            byte[] ivArray = Base64.getDecoder().decode(merchantToPayment4Json.get("iv").getAsString());
            Key aesKey = new SecretKeySpec(aesKeyArray, 0, aesKeyArray.length, "AES");
            IvParameterSpec iv = new IvParameterSpec(ivArray);

            System.out.println("[STEP5] JSON to send to merchant:" + paymentToMerchant5Json);
            paymentToMerchant5Json=HybridCrypto.encrypt(paymentToMerchant5Json,aesKey,iv,publicRsaKeyMerchant);
            System.out.println("[STEP5] Encrypted JSON to send to merchant:" + paymentToMerchant5Json);
            writeMerchant.println(paymentToMerchant5Json);

        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

    }

}
