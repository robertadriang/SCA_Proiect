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
import java.net.SocketException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class CustomerThread extends Thread {
    public PublicKey publicRsaKeyPayment;
    private PrivateKey privateRsaKeyPayment;
    private BufferedReader readCustomer;
    private PrintWriter writeCustomer;
    private Socket socket;

    public CustomerThread(PublicKey publicRsaKeyPayment, PrivateKey privateRsaKeyPayment, BufferedReader readCustomer, Socket socket) throws IOException {
        this.publicRsaKeyPayment = publicRsaKeyPayment;
        this.privateRsaKeyPayment = privateRsaKeyPayment;
        this.readCustomer = readCustomer;
        this.writeCustomer = new PrintWriter(socket.getOutputStream(), true);;
        this.socket = socket;
    }

    public void run(){
        System.out.println("[STEP3] Entering customer thread");
        System.out.println("Sending public key to client");
        writeCustomer.println(Base64.getEncoder().encodeToString(publicRsaKeyPayment.getEncoded()));

        try {
            JsonObject clientToPayment7Json =  new Gson().fromJson(readCustomer.readLine(),JsonObject.class);
            System.out.println("[STEP7] Encrypted JSON received from client:" + clientToPayment7Json);
            clientToPayment7Json=HybridCrypto.decrypt(clientToPayment7Json,privateRsaKeyPayment);
            System.out.println("[STEP7] Decrypted JSON received from client:" + clientToPayment7Json);

            String publicRsaKeyCustomerString=clientToPayment7Json.get("publicRsaKeyCustomer").getAsString();
            PublicKey publicRsaKeyClient = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(publicRsaKeyCustomerString)));

            byte[] clientSignature=Base64.getDecoder().decode(clientToPayment7Json.get("signature").getAsString().getBytes());
            int sid=clientToPayment7Json.get("sid").getAsInt();
            float amount = clientToPayment7Json.get("amount").getAsFloat();
            int NC = clientToPayment7Json.get("NC").getAsInt();
            if(Signer.validateSignature(clientSignature,publicRsaKeyClient,sid,amount,NC,publicRsaKeyCustomerString)==false){
                System.out.println("[STEP7] Client signature is not valid");
                System.exit(-10);
            }else{
                System.out.println("[STEP7] Client signature is valid");
            }
            /// TODO ADD CARD CHECKS HERE
            boolean all_valid=true;
            String response;
            if (all_valid){
                System.out.println("[STEP7] All information is valid");
                response="Ok";
            }else{
                response="NotOk";
            }

            /// Step 8
            JsonObject paymentToClient8Json=new JsonObject();
            paymentToClient8Json.addProperty("response",response);
            paymentToClient8Json.addProperty("sid",sid);
            byte[] paymentSignature=Signer.sign(privateRsaKeyPayment,response,sid,amount,NC);
            paymentToClient8Json.addProperty("signature",Base64.getEncoder().encodeToString(paymentSignature));

            // Extract AES key used for encryption
            System.out.println("JSON TO EXTRACT AES:"+clientToPayment7Json);
            byte[] aesKeyArray = Base64.getDecoder().decode(clientToPayment7Json.get("aesKey").getAsString());
            byte[] ivArray = Base64.getDecoder().decode(clientToPayment7Json.get("iv").getAsString());
            Key aesKey = new SecretKeySpec(aesKeyArray, 0, aesKeyArray.length, "AES");
            IvParameterSpec iv = new IvParameterSpec(ivArray);


            System.out.println("[STEP8] JSON to send to client:" + paymentToClient8Json);
            paymentToClient8Json=HybridCrypto.encrypt(paymentToClient8Json,aesKey,iv,publicRsaKeyClient);
            System.out.println("[STEP8] Encrypted JSON to send to client:" + paymentToClient8Json);

            writeCustomer.println(paymentToClient8Json);

        } catch (SocketException e){
            System.out.println("Socket was closed from client side");
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }

    }
}
