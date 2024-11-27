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

import java.util.List;

public class CredentialsInfoCert {
    // valid | expired | revoked | suspended
    private String status;
    // one or more certificates from the certificate chain
    private List<String> certificates;
    // the issuer distinguished name from the end entity certificate
    private String issuerDN;
    // the serial number of the end entity certificate
    private String serialNumber;
    // the subject distinguished name from the end entity certificate
    private String subjectDN;
    // the validity start date from the end entity certificate
    private String validFrom;
    // the validity end date from the end entity certificate
    private String validTo;

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public List<String> getCertificates() {
        return certificates;
    }

    public void setCertificates(List<String> certificates) {
        this.certificates = certificates;
    }

    public String getIssuerDN() {
        return issuerDN;
    }

    public void setIssuerDN(String issuerDN) {
        this.issuerDN = issuerDN;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public String getSubjectDN() {
        return subjectDN;
    }

    public void setSubjectDN(String subjectDN) {
        this.subjectDN = subjectDN;
    }

    public String getValidFrom() {
        return validFrom;
    }

    public void setValidFrom(String validFrom) {
        this.validFrom = validFrom;
    }

    public String getValidTo() {
        return validTo;
    }

    public void setValidTo(String validTo) {
        this.validTo = validTo;
    }

    @Override
    public String toString() {
        return "CredentialsInfoCert{" +
                "status='" + status + '\'' +
                ", certificates=" + certificates +
                ", issuerDN='" + issuerDN + '\'' +
                ", serialNumber='" + serialNumber + '\'' +
                ", subjectDN='" + subjectDN + '\'' +
                ", validFrom='" + validFrom + '\'' +
                ", validTo='" + validTo + '\'' +
                '}';
    }
}
