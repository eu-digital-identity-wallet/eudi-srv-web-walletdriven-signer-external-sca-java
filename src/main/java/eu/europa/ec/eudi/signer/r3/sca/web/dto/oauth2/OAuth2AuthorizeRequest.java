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

package eu.europa.ec.eudi.signer.r3.sca.web.dto.oauth2;

import jakarta.validation.constraints.NotBlank;

public class OAuth2AuthorizeRequest {
    @NotBlank
    private String response_type = "code";
    @NotBlank
    private String client_id;
    private String redirect_uri;
    private String scope;
    private String authorization_details;
    @NotBlank
    private String code_challenge;
    private String code_challenge_method = "plain";
    private String state;
    private String request_uri;

    private String lang;

    private String credentialID;
    private String signatureQualifier;
    private String numSignatures;
    private String hashes;
    private String hashAlgorithmOID;

    private String description;
    private String account_token;
    private String clientData;

    public String getResponse_type() {
        return response_type;
    }

    public void setResponse_type(String response_type) {
        this.response_type = response_type;
    }

    public String getClient_id() {
        return client_id;
    }

    public void setClient_id(String client_id) {
        this.client_id = client_id;
    }

    public String getRedirect_uri() {
        return redirect_uri;
    }

    public void setRedirect_uri(String redirect_uri) {
        this.redirect_uri = redirect_uri;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public String getAuthorization_details() {
        return authorization_details;
    }

    public void setAuthorization_details(String authorization_details) {
        this.authorization_details = authorization_details;
    }

    public String getCode_challenge() {
        return code_challenge;
    }

    public void setCode_challenge(String code_challenge) {
        this.code_challenge = code_challenge;
    }

    public String getCode_challenge_method() {
        return code_challenge_method;
    }

    public void setCode_challenge_method(String code_challenge_method) {
        this.code_challenge_method = code_challenge_method;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getRequest_uri() {
        return request_uri;
    }

    public void setRequest_uri(String request_uri) {
        this.request_uri = request_uri;
    }

    public String getLang() {
        return lang;
    }

    public void setLang(String lang) {
        this.lang = lang;
    }

    public String getCredentialID() {
        return credentialID;
    }

    public void setCredentialID(String credentialID) {
        this.credentialID = credentialID;
    }

    public String getSignatureQualifier() {
        return signatureQualifier;
    }

    public void setSignatureQualifier(String signatureQualifier) {
        this.signatureQualifier = signatureQualifier;
    }

    public String getNumSignatures() {
        return numSignatures;
    }

    public void setNumSignatures(String numSignatures) {
        this.numSignatures = numSignatures;
    }

    public String getHashes() {
        return hashes;
    }

    public void setHashes(String hashes) {
        this.hashes = hashes;
    }

    public String getHashAlgorithmOID() {
        return hashAlgorithmOID;
    }

    public void setHashAlgorithmOID(String hashAlgorithmOID) {
        this.hashAlgorithmOID = hashAlgorithmOID;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getAccount_token() {
        return account_token;
    }

    public void setAccount_token(String account_token) {
        this.account_token = account_token;
    }

    public String getClientData() {
        return clientData;
    }

    public void setClientData(String clientData) {
        this.clientData = clientData;
    }

    @Override
    public String toString() {
        return "OAuth2AuthorizeRequestDTO{" +
                "client_id='" + client_id + '\'' +
                ", redirect_uri='" + redirect_uri + '\'' +
                ", scope='" + scope + '\'' +
                ", authorization_details='" + authorization_details + '\'' +
                ", code_challenge='" + code_challenge + '\'' +
                ", code_challenge_method='" + code_challenge_method + '\'' +
                ", state='" + state + '\'' +
                ", request_uri='" + request_uri + '\'' +
                ", lang='" + lang + '\'' +
                ", credentialID='" + credentialID + '\'' +
                ", signatureQualifier='" + signatureQualifier + '\'' +
                ", numSignatures='" + numSignatures + '\'' +
                ", hashes='" + hashes + '\'' +
                ", hashAlgorithmOID='" + hashAlgorithmOID + '\'' +
                ", description='" + description + '\'' +
                ", account_token='" + account_token + '\'' +
                ", clientData='" + clientData + '\'' +
                '}';
    }



}
