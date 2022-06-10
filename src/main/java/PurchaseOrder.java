public class PurchaseOrder {
    public String orderDesc;
    public int sid;
    public float amount;
    public int NC;

    public PurchaseOrder(String orderDesc, int sid, float amount, int NC) {
        this.orderDesc = orderDesc;
        this.sid = sid;
        this.amount = amount;
        this.NC = NC;
    }
}
