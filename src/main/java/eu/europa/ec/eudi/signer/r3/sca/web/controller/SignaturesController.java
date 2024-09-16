package eu.europa.ec.eudi.signer.r3.sca.web.controller;

import eu.europa.ec.eudi.signer.r3.sca.model.DSSService;
import eu.europa.ec.eudi.signer.r3.sca.model.QtspClient;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.SignDocRequest.SignaturesSignDocRequest;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.SignaturesSignDocResponse;
import eu.europa.ec.eudi.signer.r3.sca.model.CredentialsService;
import eu.europa.ec.eudi.signer.r3.sca.model.SignatureService;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import jakarta.validation.Valid;
import java.io.InputStream;
import java.io.FileInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Properties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping(value = "/signatures")
public class SignaturesController {
    private static final Logger fileLogger = LoggerFactory.getLogger("FileLogger");

    private final SignatureService signatureService;
    private final CredentialsService credentialsService;

    @Autowired
    private QtspClient qtspClient;
    @Autowired
    private DSSService dssClient;

    private CommonTrustedCertificateSource certificateSource;


    public SignaturesController(@Autowired CredentialsService credentialsService, @Autowired SignatureService signatureService) throws Exception {

        this.credentialsService = credentialsService;
        this.signatureService = signatureService;
        this.certificateSource= new CommonTrustedCertificateSource();

        Properties properties = new Properties();

        InputStream configStream = getClass().getClassLoader().getResourceAsStream("config.properties");
        if (configStream == null) {
            throw new Exception("Arquivo config.properties não encontrado!");
        }

        properties.load(configStream);

        String certificatePath = properties.getProperty("SigningCertificate");
        if (certificatePath == null || certificatePath.isEmpty()) {
            throw new Exception("Signature Certificate Path not found in configuration file.");
        }

        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        String arrayOfStrings = properties.getProperty("TrustedCertificates");
        String [] teste = arrayOfStrings.split(";");
        for ( String path : teste){
            if (path == null || path.isEmpty()) {
                throw new Exception("Trusted Certificate Path not found in configuration file.");
            }
            FileInputStream certInput= new FileInputStream(path);
            X509Certificate certificate= (X509Certificate) certFactory.generateCertificate(certInput);
            this.certificateSource.addCertificate(new CertificateToken(certificate));

        }
    }

    @PostMapping(value = "/signDoc", consumes = "application/json", produces = "application/json")
    public SignaturesSignDocResponse signDoc(@Valid @RequestBody SignaturesSignDocRequest signDocRequest, @RequestHeader (name="Authorization") String authorizationBearerHeader) {
        fileLogger.info("Entry /signDoc");
        fileLogger.info("Signature Document Request:" + signDocRequest);
        fileLogger.info("Authorization Header: "+authorizationBearerHeader);

        if (signDocRequest.getCredentialID() == null) {
            System.out.println("To be defined: CredentialID needs to be defined in this implementation.");
            return new SignaturesSignDocResponse();
        }

        CredentialsService.CertificateResponse certificateResponse = this.credentialsService.getCertificateAndCertificateChain(signDocRequest.getRequest_uri(), signDocRequest.getCredentialID(), authorizationBearerHeader);

        if (authorizationBearerHeader == null) {
            System.out.println("To be defined: the current solution expects the credential token to be sent in the SAD.");
            return new SignaturesSignDocResponse();
        }

        if (signDocRequest.getOperationMode().equals("A")) {
            System.out.println("To be defined: the current solution doesn't support assynchronious responses.");
            return new SignaturesSignDocResponse();
        }

        if (signDocRequest.getDocuments() != null) {
            try {
                CommonTrustedCertificateSource commonTrustedCertificateSource = new CommonTrustedCertificateSource();

                Date date = new Date(signDocRequest.getSignature_date());
                return this.signatureService.handleDocumentsSignDocRequest(signDocRequest, authorizationBearerHeader, certificateResponse.getCertificate(), certificateResponse.getCertificateChain(), certificateResponse.getSignAlgo(), date);
            } catch (Exception e) {
                fileLogger.error(e.getMessage());
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_response");
            }
        }
        return new SignaturesSignDocResponse();
    }

}