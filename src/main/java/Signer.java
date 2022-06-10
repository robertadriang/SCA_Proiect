import java.security.*;

// https://www.novixys.com/blog/encrypt-sign-file-using-rsa-java/
// https://niels.nu/blog/2016/java-rsa
// https://www.geeksforgeeks.org/java-signature-sign-method-with-examples/
public class Signer {
    public static byte[] sign(PrivateKey privateRsaKey,Object... fields) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sign = Signature.getInstance("SHA256withRSA");
        sign.initSign(privateRsaKey);
        for (Object arg : fields)
            sign.update(arg.toString().getBytes());
        return sign.sign();
    }

    public static boolean validateSignature(byte[] receivedSignature,PublicKey publicRsaKey, Object... fields) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        Signature sign = Signature.getInstance("SHA256withRSA");
        sign.initVerify(publicRsaKey);
        for (Object arg : fields)
            sign.update(arg.toString().getBytes());
        return sign.verify(receivedSignature);
    }
}
