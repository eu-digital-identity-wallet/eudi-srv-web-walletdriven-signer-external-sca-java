package eu.europa.ec.eudi.signer.r3.sca.web.dto.signHash;

import java.util.List;

public class SignaturesSignHashResponse {
    private List<String> signatures;
    private String responseID;

    public List<String> getSignatures() {
        return this.signatures;
    }

    public void setSignatures(List<String> signatures) {
        this.signatures = signatures;
    }

    public String getResponseID() {
        return this.responseID;
    }

    public void setResponseID(String responseID) {
        this.responseID = responseID;
    }
}
