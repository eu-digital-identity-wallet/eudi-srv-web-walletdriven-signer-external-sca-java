package eu.europa.ec.eudi.signer.r3.sca.Controllers;

import java.beans.PropertyDescriptor;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Properties;

import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import eu.europa.ec.eudi.signer.r3.sca.DSS_Service;
import eu.europa.ec.eudi.signer.r3.sca.QtspClient;
import eu.europa.ec.eudi.signer.r3.sca.DTO.SignaturesSignDocResponse;
import eu.europa.ec.eudi.signer.r3.sca.DTO.SignaturesSignHashRequest;
import eu.europa.ec.eudi.signer.r3.sca.DTO.SignaturesSignHashResponse;
import eu.europa.ec.eudi.signer.r3.sca.DTO.ValidationInfoSignDocResponse;
import eu.europa.ec.eudi.signer.r3.sca.DTO.SignDocRequest.DocumentsSignDocRequest;
import eu.europa.ec.eudi.signer.r3.sca.DTO.SignDocRequest.SignaturesSignDocRequest;
import eu.europa.ec.eudi.signer.r3.sca.Models.SignatureDocumentForm;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import jakarta.validation.Valid;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@RestController
@RequestMapping(value = "/signatures")
public class SignaturesController {
    private static final Logger fileLogger = LoggerFactory.getLogger("FileLogger");

    @Autowired
    private QtspClient qtspClient;

    @Autowired
    private DSS_Service dssClient;

    private X509Certificate signingCertificate;

    private CommonTrustedCertificateSource certificateSource;


    public SignaturesController() throws Exception {
        
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

        FileInputStream certInputStream = new FileInputStream(certificatePath);

        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        this.signingCertificate = (X509Certificate) certFactory.generateCertificate(certInputStream);

        String arrayOfStrings = properties.getProperty("TrustedCertificates");

        String [] teste= arrayOfStrings.split(";");

        for ( String path : teste){
            if (path == null || path.isEmpty()) {
                throw new Exception("Trusted Certificate Path not found in configuration file.");
            }
            FileInputStream certInput= new FileInputStream(path);
            X509Certificate certificate= (X509Certificate) certFactory.generateCertificate(certInput);
            this.certificateSource.addCertificate(new CertificateToken(certificate));

        }
        
        certInputStream.close();

    }

    @PostMapping(value = "/signDoc", consumes = "application/json", produces = "application/json")
    public SignaturesSignDocResponse signDoc(@Valid @RequestBody SignaturesSignDocRequest signDocRequest) {

        fileLogger.info("Entry /signDoc");
        
        fileLogger.info("Signature Document Request:" + signDocRequest);

        String url = signDocRequest.getRequest_uri();
        if (signDocRequest.getCredentialID() == null) {
            System.out.println("To be defined: CredentialID needs to be defined in this implementation.");
            return new SignaturesSignDocResponse();
        }

        if (signDocRequest.getSAD() == null) {
            System.out.println(
                    "To be defined: the current solution expects the credential token to be sent in the SAD.");
            return new SignaturesSignDocResponse();
        }

        if (signDocRequest.getOperationMode().equals("A")) {
            System.out.println("To be defined: the current solution doesn't support assynchronious responses.");
            return new SignaturesSignDocResponse();
        }

        if (signDocRequest.getDocuments() != null) {
            try {
                return handleDocumentsSignDocRequest(signDocRequest, url);
            } catch (Exception e) {

            }
        }

        if (signDocRequest.getDocumentDigests() != null) {
            try {
                return handleDocumentDigestsSignDocRequest(signDocRequest, url);
            } catch (Exception e) {
            }
        }

        return new SignaturesSignDocResponse();
    }

    // i need the signing certificate before hand
    public SignaturesSignDocResponse handleDocumentsSignDocRequest(SignaturesSignDocRequest signDocRequest, String url)
            throws Exception {

        // if signature_format == C => signed_envelope_property = Attached
        // if signature_format == P => signed_envelope_property = Certification
        // if signature_format == X => signed_envelope_property = Enveloped
        // if signature_format == J => signed_envelope_property = Attached

        List<SignaturesSignHashResponse> allResponses = new ArrayList<>();
        Date date = new Date();
        SignatureDocumentForm SignatureDocumentForm = new SignatureDocumentForm();
        for (DocumentsSignDocRequest document : signDocRequest.getDocuments()) {
            DSSDocument dssDocument = dssClient.loadDssDocument(document.getDocument());
            byte[] dataToBeSigned = null;
            
            SignatureLevel aux_sign_level = DSS_Service.checkConformance_level(document.getConformance_level(), document.getSignature_format());
            DigestAlgorithm aux_digest_alg = DSS_Service.checkSignAlgDigest(document.getSignAlgo());
            SignaturePackaging aux_sign_pack = DSS_Service.checkEnvProps(document.getSigned_envelope_property());
            ASiCContainerType aux_asic_ContainerType = DSS_Service.checkASiCContainerType(document.getContainer());
            SignatureForm signatureForm= DSS_Service.checkSignForm(document.getSignature_format());

            fileLogger.info("Payload Received:{"+ "Document Hash:"+  dssDocument.getDigest(aux_digest_alg) +",conformance_level:" +document.getConformance_level()+ ","+
            "Signature Format:"+ document.getSignature_format() + "," + "Signature Algorithm:"+ document.getSignAlgo() + "," +
            "Signature Packaging:"+ document.getSigned_envelope_property() + "," + "Type of Container:"+ document.getContainer() + "}");
           
            
            SignatureDocumentForm.setDocumentToSign(dssDocument);
            SignatureDocumentForm.setSignaturePackaging(aux_sign_pack);  
            SignatureDocumentForm.setContainerType(aux_asic_ContainerType);  
            SignatureDocumentForm.setSignatureLevel(aux_sign_level);
            SignatureDocumentForm.setDigestAlgorithm(aux_digest_alg);
            SignatureDocumentForm.setSignatureForm(signatureForm);
            SignatureDocumentForm.setCertificate(this.signingCertificate);
            SignatureDocumentForm.setDate(date);
            SignatureDocumentForm.setTrustedCertificates(this.certificateSource);
            SignatureDocumentForm.setSignatureForm(signatureForm);
            SignatureDocumentForm.setCertChain(new ArrayList<>());
            SignatureDocumentForm.setEncryptionAlgorithm(EncryptionAlgorithm.ECDSA);

            fileLogger.info("SignatureDocumentForm: " + SignatureDocumentForm.getSignaturePackaging());

            dataToBeSigned = dssClient.DataToBeSignedData(SignatureDocumentForm);
            fileLogger.info("DataToBeSigned successfully created");

            if (dataToBeSigned == null) {
                return new SignaturesSignDocResponse();
            }

            String dtbs = Base64.getEncoder().encodeToString(dataToBeSigned);
            List<String> doc = new ArrayList<>();
            doc.add(dtbs);

            // As the current operation mode only supported is "S", the validity_period and
            // response_uri do not need to be defined
            SignaturesSignHashRequest signHashRequest = new SignaturesSignHashRequest(
                    signDocRequest.getCredentialID(),
                    signDocRequest.getSAD(),
                    doc,
                    null,
                    document.getSignAlgo(),
                    null,
                    signDocRequest.getOperationMode(),
                    -1,
                    null,
                    signDocRequest.getClientData());

            try {

                fileLogger.info("HTTP Request to QTSP.");
                SignaturesSignHashResponse signHashResponse = qtspClient.requestSignHash(url, signHashRequest);
                allResponses.add(signHashResponse);
                fileLogger.info("HTTP Response received.");

            } catch (Exception e) {
                fileLogger.error("Error " + e);
                e.printStackTrace();
            }
        }
        List<String> DocumentWithSignature = new ArrayList<>();

        List<String> allSignaturesObjects = new ArrayList<>();
        for (SignaturesSignHashResponse response : allResponses) {

            DocumentsSignDocRequest document = signDocRequest.getDocuments().get(0);
            DSSDocument dssDocument = dssClient.loadDssDocument(document.getDocument());

            SignatureLevel aux_sign_level = DSS_Service.checkConformance_level(document.getConformance_level(), document.getSignature_format());
            DigestAlgorithm aux_digest_alg = DSS_Service.checkSignAlgDigest(document.getSignAlgo());
            SignaturePackaging aux_sign_pack = DSS_Service.checkEnvProps(document.getSigned_envelope_property());
            ASiCContainerType aux_asic_ContainerType = DSS_Service.checkASiCContainerType(document.getContainer());
            SignatureForm signatureForm= DSS_Service.checkSignForm(document.getSignature_format());
            
            SignatureDocumentForm.setDocumentToSign(dssDocument);
            SignatureDocumentForm.setSignaturePackaging(aux_sign_pack);  
            SignatureDocumentForm.setContainerType(aux_asic_ContainerType);  
            SignatureDocumentForm.setSignatureLevel(aux_sign_level);
            SignatureDocumentForm.setDigestAlgorithm(aux_digest_alg);
            SignatureDocumentForm.setSignatureForm(signatureForm);
            SignatureDocumentForm.setCertificate(this.signingCertificate);
            SignatureDocumentForm.setDate(date);
            SignatureDocumentForm.setTrustedCertificates(this.certificateSource);
            SignatureDocumentForm.setSignatureForm(signatureForm);
            SignatureDocumentForm.setCertChain(new ArrayList<>());
            SignatureDocumentForm.setEncryptionAlgorithm(EncryptionAlgorithm.ECDSA);
            
            
            if (response.getSignatures() != null) {
                byte[] signature = Base64.getDecoder().decode(response.getSignatures().get(0));
                SignatureDocumentForm.setSignatureValue(signature);
                DSSDocument docSigned = dssClient.signDocument(SignatureDocumentForm);
                fileLogger.info("Document successfully signed.");

                try {
                    if (document.getContainer().equals("ASiC-E")) {
                        if (document.getSignature_format().equals("C") || document.getSignature_format().equals("X")) {
                            
                            docSigned.setMimeType(MimeType.fromMimeTypeString("application/vnd.etsi.asic-e+zip"));
                            docSigned.save("tests/exampleSigned.cse");

                            File file = new File("tests/exampleSigned.cse");
                            byte[] pdfBytes = Files.readAllBytes(file.toPath());

                            DocumentWithSignature.add(Base64.getEncoder().encodeToString(pdfBytes));
                        }

                    }
                    else if (document.getContainer().equals("ASiC-S")) {
                        if (document.getSignature_format().equals("C") || document.getSignature_format().equals("X")) {

                            docSigned.setMimeType(MimeType.fromMimeTypeString("application/vnd.etsi.asic-s+zip"));
                            docSigned.save("tests/exampleSigned.scs");

                            File file = new File("tests/exampleSigned.scs");
                            byte[] pdfBytes = Files.readAllBytes(file.toPath());

                            DocumentWithSignature.add(Base64.getEncoder().encodeToString(pdfBytes));
                        }

                    }
                    else if (document.getSignature_format().equals("J")) {

                        docSigned.setMimeType(MimeType.fromMimeTypeString("application/jose"));
                        docSigned.save("tests/exampleSigned.json");

                        File file = new File("tests/exampleSigned.json");
                        byte[] jsonBytes = Files.readAllBytes(file.toPath());

                        DocumentWithSignature.add(Base64.getEncoder().encodeToString(jsonBytes));
                    }
                    else if (document.getSignature_format().equals("X")) {

                        docSigned.setMimeType(MimeType.fromMimeTypeString("text/xml"));
                        docSigned.save("tests/exampleSigned.xml");

                        File file = new File("tests/exampleSigned.xml");
                        byte[] xmlBytes = Files.readAllBytes(file.toPath());
                        DocumentWithSignature.add(Base64.getEncoder().encodeToString(xmlBytes));
                    }
                    else {
                        
                        docSigned.setMimeType(MimeType.fromMimeTypeString("application/pdf"));
                        docSigned.save("tests/exampleSigned.pdf");

                        File file = new File("tests/exampleSigned.pdf");
                        byte[] pdfBytes = Files.readAllBytes(file.toPath());

                        DocumentWithSignature.add(Base64.getEncoder().encodeToString(pdfBytes));
                    }

                } catch (Exception e) {
                    e.printStackTrace();
                }
            }

            allSignaturesObjects.addAll(response.getSignatures());
        }

        ValidationInfoSignDocResponse validationInfo = null;
        if (signDocRequest.getReturnValidationInfo()) {
            // TODO: obtain the validation info....
            validationInfo = new ValidationInfoSignDocResponse();
        }

        SignaturesSignDocResponse signDocResponse = new SignaturesSignDocResponse(
                DocumentWithSignature,
                allSignaturesObjects,
                null,
                validationInfo);
        
        return signDocResponse;

    }

    public SignaturesSignDocResponse handleDocumentDigestsSignDocRequest(SignaturesSignDocRequest signDocRequest,
            String url)
            throws Exception {

        // for each document digests....
        List<SignaturesSignHashResponse> allResponses = new ArrayList<>();
        for (int i = 0; i < signDocRequest.getDocumentDigests().size(); i++) {
            SignaturesSignHashRequest signHashRequest = new SignaturesSignHashRequest(
                    signDocRequest.getCredentialID(),
                    signDocRequest.getSAD(),
                    signDocRequest.getDocumentDigests().get(i).getHashes(),
                    signDocRequest.getDocumentDigests().get(i).getHashAlgorithmOID(),
                    signDocRequest.getDocumentDigests().get(i).getSignAlgo(),
                    signDocRequest.getDocumentDigests().get(i).getSignAlgoParams(),
                    signDocRequest.getOperationMode(),
                    signDocRequest.getValidity_period(),
                    signDocRequest.getResponse_uri(),
                    signDocRequest.getClientData());

            SignaturesSignHashResponse signHashResponse = qtspClient.requestSignHash(url, signHashRequest);
            allResponses.add(signHashResponse);
        }

        List<String> allSignaturesObjects = new ArrayList<>();
        for (int i = 0; i < allResponses.size(); i++) {
            allSignaturesObjects.addAll(allResponses.get(i).getSignatures());
        }

        ValidationInfoSignDocResponse validationInfo = null;
        if (signDocRequest.getReturnValidationInfo()) {
            // TODO: obtain the validation info....
            validationInfo = new ValidationInfoSignDocResponse();
        }

        SignaturesSignDocResponse signDocResponse = new SignaturesSignDocResponse(
                null,
                allSignaturesObjects,
                null,
                validationInfo);

        return signDocResponse;

    }
}
