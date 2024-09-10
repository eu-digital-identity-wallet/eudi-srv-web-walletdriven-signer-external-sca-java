package eu.europa.ec.eudi.signer.r3.sca.DTO.SignDocRequest;

import eu.europa.ec.eudi.signer.r3.sca.Validators.SignDocRequestConstraintAnnotation;

import java.util.List;
import com.fasterxml.jackson.annotation.JsonProperty;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;

@SignDocRequestConstraintAnnotation
public class SignaturesSignDocRequest {
    private String credentialID;
    private String signatureQualifier;
    @Valid
    private List<DocumentsSignDocRequest> documents;
    private String operationMode = "S";
    private int validity_period = -1;
    private String response_uri;
    private String clientData;
    private Boolean returnValidationInfo = false;
    @NotBlank
    private String request_uri;
    private String hashAlgorithmOID;

    public SignaturesSignDocRequest() {
    }

    @JsonProperty
    public String getCredentialID() {
        return credentialID;
    }

    @JsonProperty
    public void setCredentialID(String credentialID) {
        this.credentialID = credentialID;
    }

    @JsonProperty
    public String getSignatureQualifier() {
        return signatureQualifier;
    }

    @JsonProperty
    public void setSignatureQualifier(String signatureQualifier) {
        this.signatureQualifier = signatureQualifier;
    }

    @JsonProperty
    public List<DocumentsSignDocRequest> getDocuments() {
        return documents;
    }

    @JsonProperty
    public void setDocuments(List<DocumentsSignDocRequest> documents) {
        this.documents = documents;
    }

    @JsonProperty
    public String getOperationMode() {
        return operationMode;
    }

    @JsonProperty
    public void setOperationMode(String operationMode) {
        this.operationMode = operationMode;
    }

    @JsonProperty
    public int getValidity_period() {
        return validity_period;
    }

    @JsonProperty
    public void setValidity_period(int validity_period) {
        this.validity_period = validity_period;
    }

    @JsonProperty
    public String getResponse_uri() {
        return response_uri;
    }

    @JsonProperty
    public void setResponse_uri(String response_uri) {
        this.response_uri = response_uri;
    }

    @JsonProperty
    public String getClientData() {
        return clientData;
    }

    @JsonProperty
    public void setClientData(String clientData) {
        this.clientData = clientData;
    }

    @JsonProperty
    public Boolean getReturnValidationInfo() {
        return returnValidationInfo;
    }

    @JsonProperty
    public void setReturnValidationInfo(Boolean returnValidationInfo) {
        this.returnValidationInfo = returnValidationInfo;
    }

    @JsonProperty
    public String getRequest_uri() {
        return request_uri;
    }

    @JsonProperty
    public void setRequest_uri(String request_uri) {
        this.request_uri = request_uri;
    }

    public String getHashAlgorithmOID() {
        return hashAlgorithmOID;
    }

    public void setHashAlgorithmOID(String hashAlgorithmOID) {
        this.hashAlgorithmOID = hashAlgorithmOID;
    }

    @java.lang.Override
    public java.lang.String toString() {
        return "SignaturesSignDocRequest{" +
                "credentialID=" + credentialID +
                ", signatureQualifier=" + signatureQualifier +
                ", documents=" + documents +
                ", operationMode=" + operationMode +
                ", validity_period=" + validity_period +
                ", response_uri=" + response_uri +
                ", clientData=" + clientData +
                ", returnValidationInfo=" + returnValidationInfo +
                ", request_uri=" + request_uri +
                '}';
    }
}
