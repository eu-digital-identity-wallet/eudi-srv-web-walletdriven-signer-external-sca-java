/*
 Copyright 2024 European Commission

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

package eu.europa.ec.eudi.signer.r3.sca.web.dto.qtsp.oauth2;

import eu.europa.ec.eudi.signer.r3.sca.web.dto.signDoc.DocumentsSignDocRequest;
import java.util.List;

public class CredentialAuthorizationRequest {
    private String credentialID;
    private List<DocumentsSignDocRequest> documents;

    private String hashAlgorithmOID;

    private String authorizationServerUrl;
    private String resourceServerUrl;

    private String redirectUri; // url where to post the file and redirect after the end of the signature flow

    private String clientData;

    public String getCredentialID() {
        return credentialID;
    }

    public void setCredentialID(String credentialID) {
        this.credentialID = credentialID;
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

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    @Override
    public String toString() {
        return "CredentialAuthorizationRequest{" +
              "credentialID='" + credentialID + '\'' +
              ", documents=" + documents +
              ", hashAlgorithmOID='" + hashAlgorithmOID + '\'' +
              ", authorizationServerUrl='" + authorizationServerUrl + '\'' +
              ", resourceServerUrl='" + resourceServerUrl + '\'' +
              ", clientData='" + clientData + '\'' +
              '}';
    }
}
