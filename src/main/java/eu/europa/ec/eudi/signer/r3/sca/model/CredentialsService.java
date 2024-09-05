package eu.europa.ec.eudi.signer.r3.sca.model;

import eu.europa.ec.eudi.signer.r3.sca.DTO.CredentialsInfo.CredentialsInfoRequest;
import eu.europa.ec.eudi.signer.r3.sca.DTO.CredentialsInfo.CredentialsInfoResponse;
import eu.europa.ec.eudi.signer.r3.sca.QtspClient;
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

    public CredentialsService(@Autowired QtspClient qtspClient){
        this.qtspClient = qtspClient;
    }

    // get the certificate and certificate chain of the credentialID
    public List<X509Certificate> getCertificateAndCertificateChain(String qtspUrl, String credentialId, String authorizationBearerHeader){
        CredentialsInfoRequest infoRequest = new CredentialsInfoRequest();
        infoRequest.setCredentialID(credentialId);
        infoRequest.setCertificates("chain");
        infoRequest.setCertInfo(true);

        CredentialsInfoResponse infoResponse = this.qtspClient.requestCredentialInfo(qtspUrl, infoRequest, authorizationBearerHeader);
        List<String> certificates = infoResponse.getCert().getCertificates();

        List<X509Certificate> x509Certificates = new ArrayList<>();
        for(String c: certificates){
            try{
                X509Certificate cert = base64DecodeCertificate(c);
                x509Certificates.add(cert);
            }
            catch (Exception e){
                e.printStackTrace();
            }
        }
        return x509Certificates;
    }

    public X509Certificate base64DecodeCertificate(String certificate) throws Exception{
        byte[] certificateBytes = Base64.getDecoder().decode(certificate);
        ByteArrayInputStream inputStream  =  new ByteArrayInputStream(certificateBytes);
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        return (X509Certificate)certFactory.generateCertificate(inputStream);
    }



}
