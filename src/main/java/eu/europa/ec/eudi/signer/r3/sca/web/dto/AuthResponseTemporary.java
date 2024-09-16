package eu.europa.ec.eudi.signer.r3.sca.web.dto;

public class AuthResponseTemporary {
    private String location_wallet;
    private String session_cookie;
    private long signature_date;

    public AuthResponseTemporary(String location, String cookie){
        this.location_wallet = location;
        this.session_cookie = cookie;
    }

    public String getLocation_wallet() {
        return location_wallet;
    }

    public void setLocation_wallet(String location_wallet) {
        this.location_wallet = location_wallet;
    }

    public String getSession_cookie() {
        return session_cookie;
    }

    public void setSession_cookie(String session_cookie) {
        this.session_cookie = session_cookie;
    }

    public long getSignature_date() {
        return signature_date;
    }

    public void setSignature_date(long signature_date) {
        this.signature_date = signature_date;
    }
}
