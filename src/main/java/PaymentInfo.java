public class PaymentInfo {
    public String cardN;
    public String cardExp;
    public String cCode;
    public int sid;
    public float amount;
    public String publicRsaKeyCustomer;
    public int NC;
    public int mId;

    public PaymentInfo(String cardN, String cardExp, String cCode, int sid, float amount, String publicRsaKeyCustomer, int NC, int mId) {
        this.cardN = cardN;
        this.cardExp = cardExp;
        this.cCode = cCode;
        this.sid = sid;
        this.amount = amount;
        this.publicRsaKeyCustomer = publicRsaKeyCustomer;
        this.NC = NC;
        this.mId = mId;
    }
}
