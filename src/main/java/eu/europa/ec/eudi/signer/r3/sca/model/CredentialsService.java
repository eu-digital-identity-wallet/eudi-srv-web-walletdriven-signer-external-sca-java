package eu.europa.ec.eudi.signer.r3.sca.model;

import eu.europa.ec.eudi.signer.r3.sca.web.dto.CredentialsInfo.CredentialsInfoRequest;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.CredentialsInfo.CredentialsInfoResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@Service
public class CredentialsService {

    private final QtspClient qtspClient;
    private static final Logger logger = LoggerFactory.getLogger(CredentialsService.class);

    public CredentialsService(@Autowired QtspClient qtspClient){
        this.qtspClient = qtspClient;
    }

    public static class CertificateResponse {
        private X509Certificate certificate;
        private List<X509Certificate> certificateChain;
        private List<String> signAlgo;

        public CertificateResponse(X509Certificate certificate, List<X509Certificate> certificateChain, List<String> signAlgo) {
            this.certificate = certificate;
            this.certificateChain = certificateChain;
            this.signAlgo = signAlgo;
        }

        public X509Certificate getCertificate() {
            return certificate;
        }

        public void setCertificate(X509Certificate certificate) {
            this.certificate = certificate;
        }

        public List<X509Certificate> getCertificateChain() {
            return certificateChain;
        }

        public void setCertificateChain(List<X509Certificate> certificateChain) {
            this.certificateChain = certificateChain;
        }

        public List<String> getSignAlgo() {
            return signAlgo;
        }

        public void setSignAlgo(List<String> signAlgo) {
            this.signAlgo = signAlgo;
        }
    }

    // get the certificate and certificate chain of the credentialID
    public CertificateResponse getCertificateAndCertificateChain(String qtspUrl, String credentialId, String authorizationBearerHeader){
        CredentialsInfoRequest infoRequest = new CredentialsInfoRequest();
        infoRequest.setCredentialID(credentialId);
        infoRequest.setCertificates("chain");
        infoRequest.setCertInfo(true);

        CredentialsInfoResponse infoResponse = this.qtspClient.requestCredentialInfo(qtspUrl, infoRequest, authorizationBearerHeader);
        List<String> certificates = infoResponse.getCert().getCertificates();
        List<String> keyAlgo = infoResponse.getKey().getAlgo();

        List<X509Certificate> x509Certificates = new ArrayList<>();
        for(String c: certificates){
            try{
                X509Certificate cert = base64DecodeCertificate(c);
                logger.info("{}: {}", cert.getSubjectX500Principal(), cert.getSerialNumber());
                x509Certificates.add(cert);
            }
            catch (Exception e){
                e.printStackTrace();
            }
        }
        int size = x509Certificates.size();
        return new CertificateResponse(x509Certificates.get(0), x509Certificates.subList(1, size), keyAlgo);
    }

    private X509Certificate base64DecodeCertificate(String certificate) throws Exception{
        byte[] certificateBytes = Base64.getDecoder().decode(certificate);
        ByteArrayInputStream inputStream  =  new ByteArrayInputStream(certificateBytes);
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        return (X509Certificate)certFactory.generateCertificate(inputStream);
    }
}
