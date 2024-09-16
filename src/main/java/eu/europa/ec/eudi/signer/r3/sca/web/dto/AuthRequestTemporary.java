package eu.europa.ec.eudi.signer.r3.sca.web.dto;

public class AuthRequestTemporary {
    private String url;
    private String cookie;

    // Getters e Setters
    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getCookie() {
        return cookie;
    }

    public void setCookie(String cookie) {
        this.cookie = cookie;
    }
}
