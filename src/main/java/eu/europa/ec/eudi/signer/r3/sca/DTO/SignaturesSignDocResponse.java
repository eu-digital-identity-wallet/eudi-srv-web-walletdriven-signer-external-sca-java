package eu.europa.ec.eudi.signer.r3.sca.DTO;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class SignaturesSignDocResponse {
    private List<String> documentWithSignature;
    private List<String> signatureObject;
    private String responseID;
    private ValidationInfoSignDocResponse validationInfo;

    public SignaturesSignDocResponse() {
        this.documentWithSignature = null;
        this.signatureObject = null;
        this.responseID = null;
        this.validationInfo = null;
    }

    public SignaturesSignDocResponse(List<String> documentWithSignature, List<String> signatureObject,
            String responseID, ValidationInfoSignDocResponse validationInfo) {
        this.documentWithSignature = documentWithSignature;
        this.signatureObject = signatureObject;
        this.responseID = responseID;
        this.validationInfo = validationInfo;
    }

    public List<String> getDocumentWithSignature() {
        return documentWithSignature;
    }

    public void setDocumentWithSignature(List<String> documentWithSignature) {
        this.documentWithSignature = documentWithSignature;
    }

    public List<String> getSignatureObject() {
        return signatureObject;
    }

    public void setSignatureObject(List<String> signatureObject) {
        this.signatureObject = signatureObject;
    }

    public String getResponseID() {
        return responseID;
    }

    public void setResponseID(String responseID) {
        this.responseID = responseID;
    }

    public ValidationInfoSignDocResponse getValidationInfo() {
        return validationInfo;
    }

    public void setValidationInfo(ValidationInfoSignDocResponse validationInfo) {
        this.validationInfo = validationInfo;
    }

    @java.lang.Override
    public java.lang.String toString() {
        return "SignaturesSignDocResponse{" +
                "documentWithSignature=" + documentWithSignature +
                ", signatureObject=" + signatureObject +
                ", responseID='" + responseID + '\'' +
                ", validationInfo=" + validationInfo.toString() +
                '}';
    }
}
