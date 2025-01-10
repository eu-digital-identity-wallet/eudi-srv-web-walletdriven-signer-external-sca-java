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

package eu.europa.ec.eudi.signer.r3.sca.web.dto.qtsp.signDoc;

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
