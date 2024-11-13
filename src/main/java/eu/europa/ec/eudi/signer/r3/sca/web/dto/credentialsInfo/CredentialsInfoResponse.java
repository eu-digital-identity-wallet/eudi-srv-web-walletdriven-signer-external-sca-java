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

package eu.europa.ec.eudi.signer.r3.sca.web.dto.credentialsInfo;

import jakarta.validation.constraints.NotBlank;

public class CredentialsInfoResponse {
    private String description;
    private String signatureQualifier;
    private CredentialsInfoKey key;
    private CredentialsInfoCert cert;
    private CredentialsInfoAuth auth;
    // 1 | 2
    private String SCAL = "1";
    // >= 1
    @NotBlank
    private int multisign;
    private String lang;

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getSignatureQualifier() {
        return signatureQualifier;
    }

    public void setSignatureQualifier(String signatureQualifier) {
        this.signatureQualifier = signatureQualifier;
    }

    public CredentialsInfoKey getKey() {
        return key;
    }

    public void setKey(CredentialsInfoKey key) {
        this.key = key;
    }

    public CredentialsInfoCert getCert() {
        return cert;
    }

    public void setCert(CredentialsInfoCert cert) {
        this.cert = cert;
    }

    public CredentialsInfoAuth getAuth() {
        return auth;
    }

    public void setAuth(CredentialsInfoAuth auth) {
        this.auth = auth;
    }

    public String getSCAL() {
        return SCAL;
    }

    public void setSCAL(String SCAL) {
        this.SCAL = SCAL;
    }

    public int getMultisign() {
        return multisign;
    }

    public void setMultisign(int multisign) {
        this.multisign = multisign;
    }

    public String getLang() {
        return lang;
    }

    public void setLang(String lang) {
        this.lang = lang;
    }

    @Override
    public String toString() {
        return "CredentialsInfoResponse{" +
                "description='" + description + '\'' +
                ", signatureQualifier='" + signatureQualifier + '\'' +
                ", key='" + key.toString() +
                ", cert='" + cert.toString()+
                ", auth='" + auth.toString() +
                ", SCAL='" + SCAL + '\'' +
                ", multisign=" + multisign +
                ", lang='" + lang + '\'' +
                '}';
    }
}
