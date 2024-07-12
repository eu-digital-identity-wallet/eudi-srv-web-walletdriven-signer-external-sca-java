package eu.europa.ec.eudi.signer.r3.sca.DTO;

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
