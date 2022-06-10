import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;

public class PaymentGateway {
    public PublicKey publicRsaKeyPayment;
    private PrivateKey privateRsaKeyPayment;

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        PaymentGateway paymentGateway = new PaymentGateway();
        paymentGateway.start(7777);
    }

    private void start(int port) throws NoSuchAlgorithmException, IOException {
        System.out.println("Started gateway");
        createKeys(); /// Trebuie generat l afiecare pas?
        ServerSocket serverSocket = new ServerSocket(port);
        while (true) {

            Socket clientSocket = serverSocket.accept();
            BufferedReader readClient = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            String connector = readClient.readLine();
            System.out.println(connector);
            if (connector.equals("customer")) {
                System.out.println("[STEP3] A customer requested a connectin to PG");
                new CustomerThread(publicRsaKeyPayment,privateRsaKeyPayment, readClient,clientSocket).start();
            } else if (connector.equals("merchant")) {
                System.out.println("[STEP4] A customer requested a connectin to PG");
                new MerchantThread(publicRsaKeyPayment,privateRsaKeyPayment, readClient,clientSocket).start();
            } else {
                System.out.println("[STEP34] The customer identity is not known");
                clientSocket.close();
            }
        }


    }

    private void createKeys() throws NoSuchAlgorithmException {
        KeyPairGenerator rsaKeyGen = KeyPairGenerator.getInstance("RSA");
        rsaKeyGen.initialize(2048);
        KeyPair keyPair = rsaKeyGen.generateKeyPair();

        publicRsaKeyPayment = keyPair.getPublic();
        privateRsaKeyPayment = keyPair.getPrivate();
    }
}
