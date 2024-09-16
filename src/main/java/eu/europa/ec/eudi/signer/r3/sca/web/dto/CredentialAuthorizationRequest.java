package eu.europa.ec.eudi.signer.r3.sca.web.dto;

import eu.europa.ec.eudi.signer.r3.sca.web.dto.SignDocRequest.DocumentsSignDocRequest;
import java.util.List;

public class CredentialAuthorizationRequest {

    private String credentialID;
    private String numSignatures;
    private List<DocumentsSignDocRequest> documents;
    private String hashAlgorithmOID;
    private String authorizationServerUrl;
    private String resourceServerUrl;
    private String clientData;

    public String getCredentialID() {
        return credentialID;
    }

    public void setCredentialID(String credentialID) {
        this.credentialID = credentialID;
    }

    public String getNumSignatures() {
        return numSignatures;
    }

    public void setNumSignatures(String numSignatures) {
        this.numSignatures = numSignatures;
    }

    public List<DocumentsSignDocRequest> getDocuments() {
        return documents;
    }

    public void setDocuments(List<DocumentsSignDocRequest> documents) {
        this.documents = documents;
    }

    public String getHashAlgorithmOID() {
        return hashAlgorithmOID;
    }

    public void setHashAlgorithmOID(String hashAlgorithmOID) {
        this.hashAlgorithmOID = hashAlgorithmOID;
    }

    public String getClientData() {
        return clientData;
    }

    public void setClientData(String clientData) {
        this.clientData = clientData;
    }

    public String getAuthorizationServerUrl() {
        return authorizationServerUrl;
    }

    public void setAuthorizationServerUrl(String authorizationServerUrl) {
        this.authorizationServerUrl = authorizationServerUrl;
    }

    public String getResourceServerUrl() {
        return resourceServerUrl;
    }

    public void setResourceServerUrl(String resourceServerUrl) {
        this.resourceServerUrl = resourceServerUrl;
    }

    @Override
    public String toString() {
        return "CredentialAuthorizationRequest{" +
              "credentialID='" + credentialID + '\'' +
              ", numSignatures='" + numSignatures + '\'' +
              ", documents=" + documents +
              ", hashAlgorithmOID='" + hashAlgorithmOID + '\'' +
              ", authorizationServerUrl='" + authorizationServerUrl + '\'' +
              ", resourceServerUrl='" + resourceServerUrl + '\'' +
              ", clientData='" + clientData + '\'' +
              '}';
    }
}
