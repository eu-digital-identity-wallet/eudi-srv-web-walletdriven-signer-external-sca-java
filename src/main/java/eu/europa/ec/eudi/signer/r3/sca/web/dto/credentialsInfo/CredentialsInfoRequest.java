package eu.europa.ec.eudi.signer.r3.sca.web.dto.credentialsInfo;

public class CredentialsInfoRequest {
    private String credentialID;
    // none | single | chain
    private String certificates = "single";
    private Boolean certInfo = false;
    private Boolean authInfo = false;
    private String lang;
    private String clientData;

    public String getCredentialID() {
        return credentialID;
    }

    public void setCredentialID(String credentialID) {
        this.credentialID = credentialID;
    }

    public String getCertificates() {
        return certificates;
    }

    public void setCertificates(String certificates) {
        this.certificates = certificates;
    }

    public Boolean getCertInfo() {
        return certInfo;
    }

    public void setCertInfo(Boolean certInfo) {
        this.certInfo = certInfo;
    }

    public Boolean getAuthInfo() {
        return authInfo;
    }

    public void setAuthInfo(Boolean authInfo) {
        this.authInfo = authInfo;
    }

    public String getLang() {
        return lang;
    }

    public void setLang(String lang) {
        this.lang = lang;
    }

    public String getClientData() {
        return clientData;
    }

    public void setClientData(String clientData) {
        this.clientData = clientData;
    }

    @Override
    public String toString() {
        return "CredentialsInfoRequestDTO{" +
                "credentialID='" + credentialID + '\'' +
                ", certificates='" + certificates + '\'' +
                ", certInfo=" + certInfo +
                ", authInfo=" + authInfo +
                ", lang='" + lang + '\'' +
                ", clientData='" + clientData + '\'' +
                '}';
    }
}
