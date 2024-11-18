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

package eu.europa.ec.eudi.signer.r3.sca.web.dto.signDoc;

import java.util.List;

public class ValidationInfoSignDocResponse {
    private List<String> ocsp;
    private List<String> crl;
    private List<String> certificates;

    public ValidationInfoSignDocResponse() {
    }

    public ValidationInfoSignDocResponse(List<String> ocsp, List<String> crl, List<String> certificates) {
        this.ocsp = ocsp;
        this.crl = crl;
        this.certificates = certificates;
    }

    public List<String> getOcsp() {
        return ocsp;
    }

    public void setOcsp(List<String> ocsp) {
        this.ocsp = ocsp;
    }

    public List<String> getCrl() {
        return crl;
    }

    public void setCrl(List<String> crl) {
        this.crl = crl;
    }

    public List<String> getCertificates() {
        return certificates;
    }

    public void setCertificates(List<String> certificates) {
        this.certificates = certificates;
    }

    @java.lang.Override
    public java.lang.String toString() {
        return "ValidationInfoSignDocResponse{" +
                "ocsp=" + ocsp +
                ", crl=" + crl +
                ", certificates=" + certificates +
                '}';
    }
}
