package eu.europa.ec.eudi.signer.r3.sca.model;

import eu.europa.ec.eudi.signer.r3.sca.web.dto.SignDocRequest.DocumentsSignDocRequest;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.SignDocRequest.SignaturesSignDocRequest;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.SignaturesSignDocResponse;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.SignaturesSignHashRequest;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.SignaturesSignHashResponse;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.ValidationInfoSignDocResponse;
import eu.europa.esig.dss.enumerations.*;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;

import java.io.File;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;

@Service
public class SignatureService {

    private static final Logger fileLogger = LoggerFactory.getLogger("FileLogger");
    private final QtspClient qtspClient;
    private final DSSService dssClient;

    public SignatureService(@Autowired QtspClient qtspClient, @Autowired DSSService dssClient){
        this.qtspClient = qtspClient;
        this.dssClient = dssClient;
    }

    public List<String> calculateHashValue(List<DocumentsSignDocRequest> documents, X509Certificate signingCertificate, List<X509Certificate> certificateChain, String hashAlgorithmOID, Date date, CommonTrustedCertificateSource certificateSource) throws Exception{
        List<String> hashes = new ArrayList<>();
        for (DocumentsSignDocRequest document : documents) {
            DSSDocument dssDocument = dssClient.loadDssDocument(document.getDocument());

            SignatureLevel aux_sign_level = DSSService.checkConformance_level(document.getConformance_level(), document.getSignature_format());
            DigestAlgorithm aux_digest_alg = DSSService.checkSignAlgDigest(hashAlgorithmOID);
            SignaturePackaging aux_sign_pack = DSSService.checkEnvProps(document.getSigned_envelope_property());
            ASiCContainerType aux_asic_ContainerType = DSSService.checkASiCContainerType(document.getContainer());
            SignatureForm signatureForm = DSSService.checkSignForm(document.getSignature_format());

            fileLogger.info("Session_id:"+ RequestContextHolder.currentRequestAttributes().getSessionId() +",Payload Received:{"+ "Document Hash:"+  dssDocument.getDigest(aux_digest_alg) +",conformance_level:" +document.getConformance_level()+ ","+
                  "Signature Format:"+ document.getSignature_format() + "," + "Hash Algorithm OID:"+ hashAlgorithmOID + "," +
                  "Signature Packaging:"+ document.getSigned_envelope_property() + "," + "Type of Container:"+ document.getContainer() + "}");

            SignatureDocumentForm signatureDocumentForm = new SignatureDocumentForm();

            signatureDocumentForm.setDocumentToSign(dssDocument);
            signatureDocumentForm.setSignaturePackaging(aux_sign_pack);
            signatureDocumentForm.setContainerType(aux_asic_ContainerType);
            signatureDocumentForm.setSignatureLevel(aux_sign_level);
            signatureDocumentForm.setDigestAlgorithm(aux_digest_alg);
            signatureDocumentForm.setSignatureForm(signatureForm);
            signatureDocumentForm.setCertificate(signingCertificate);
            signatureDocumentForm.setDate(date);
            signatureDocumentForm.setTrustedCertificates(certificateSource);
            signatureDocumentForm.setSignatureForm(signatureForm);
            signatureDocumentForm.setCertChain(new ArrayList<>());
            signatureDocumentForm.setEncryptionAlgorithm(EncryptionAlgorithm.RSA);

            byte[] dataToBeSigned = dssClient.DataToBeSignedData(signatureDocumentForm);
            fileLogger.info("Session_id:"+ RequestContextHolder.currentRequestAttributes().getSessionId() +",DataToBeSigned successfully created");

            if (dataToBeSigned == null) continue;

            String dataToBeSignedStringEncoded = Base64.getEncoder().encodeToString(dataToBeSigned);
            String dataToBeSignedURLEncoded = URLEncoder.encode(dataToBeSignedStringEncoded, StandardCharsets.UTF_8);
            hashes.add(dataToBeSignedURLEncoded);
        }
        return hashes;
    }


    // i need the signing certificate before hand
    public SignaturesSignDocResponse handleDocumentsSignDocRequest(SignaturesSignDocRequest signDocRequest, String authorizationBearerHeader, X509Certificate certificate, List<X509Certificate> certificateChain, List<String> signAlgo, Date date) throws Exception {
        CommonTrustedCertificateSource certificateSource = new CommonTrustedCertificateSource();

        List<String> hashes = calculateHashValue(signDocRequest.getDocuments(), certificate, certificateChain, signDocRequest.getHashAlgorithmOID(), date, certificateSource);

        SignaturesSignHashResponse signHashResponse = null;
        try {
            // As the current operation mode only supported is "S", the validity_period and response_uri do not need to be defined
            SignaturesSignHashRequest signHashRequest = new SignaturesSignHashRequest(signDocRequest.getCredentialID(),
                  null, hashes, signDocRequest.getHashAlgorithmOID(), signAlgo.get(0), null, signDocRequest.getOperationMode(),
                  -1, null, signDocRequest.getClientData());

            fileLogger.info("Session_id:"+ RequestContextHolder.currentRequestAttributes().getSessionId() +",HTTP Request to QTSP.");
            signHashResponse = qtspClient.requestSignHash(signDocRequest.getRequest_uri(), signHashRequest, authorizationBearerHeader);
            fileLogger.info("Session_id:"+ RequestContextHolder.currentRequestAttributes().getSessionId() +",HTTP Response received.");

        } catch (Exception e) {
            e.printStackTrace();
        }

        assert signHashResponse != null;
        if(signHashResponse.getSignatures().size() != signDocRequest.getDocuments().size()){
            return new SignaturesSignDocResponse();
        }

        List<String> allSignaturesObjects = signHashResponse.getSignatures();
        List<String> DocumentWithSignature = new ArrayList<>();
        for(int i = 0; i < signDocRequest.getDocuments().size(); i++){
            DocumentsSignDocRequest document = signDocRequest.getDocuments().get(i);
            DSSDocument dssDocument = dssClient.loadDssDocument(document.getDocument());


            SignatureLevel aux_sign_level = DSSService.checkConformance_level(document.getConformance_level(), document.getSignature_format());
            DigestAlgorithm aux_digest_alg = DSSService.checkSignAlgDigest(signDocRequest.getHashAlgorithmOID());
            SignaturePackaging aux_sign_pack = DSSService.checkEnvProps(document.getSigned_envelope_property());
            ASiCContainerType aux_asic_ContainerType = DSSService.checkASiCContainerType(document.getContainer());
            SignatureForm signatureForm= DSSService.checkSignForm(document.getSignature_format());

            SignatureDocumentForm signatureDocumentForm = new SignatureDocumentForm();
            signatureDocumentForm.setDocumentToSign(dssDocument);
            signatureDocumentForm.setSignaturePackaging(aux_sign_pack);
            signatureDocumentForm.setContainerType(aux_asic_ContainerType);
            signatureDocumentForm.setSignatureLevel(aux_sign_level);
            signatureDocumentForm.setDigestAlgorithm(aux_digest_alg);
            signatureDocumentForm.setSignatureForm(signatureForm);
            signatureDocumentForm.setCertificate(certificate);
            signatureDocumentForm.setDate(date);
            signatureDocumentForm.setTrustedCertificates(certificateSource);
            signatureDocumentForm.setSignatureForm(signatureForm);
            signatureDocumentForm.setCertChain(new ArrayList<>());
            signatureDocumentForm.setEncryptionAlgorithm(EncryptionAlgorithm.RSA);

            byte[] signature = Base64.getDecoder().decode(signHashResponse.getSignatures().get(i));
            signatureDocumentForm.setSignatureValue(signature);
            DSSDocument docSigned = dssClient.signDocument(signatureDocumentForm);
            fileLogger.info("Session_id:"+ RequestContextHolder.currentRequestAttributes().getSessionId() +",Document successfully signed.");
            //DSSDocument docSigned = dssClient.getSignedDocument(dssDocument, signature, certificate, certificateChain, signAlgo.get(0), signDocRequest.getHashAlgorithmOID());

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
                fileLogger.error("invalid request: "+ e.getMessage());
                throw e;
            }
        }

        allSignaturesObjects.addAll(signHashResponse.getSignatures());

        ValidationInfoSignDocResponse validationInfo = null;
        if (signDocRequest.getReturnValidationInfo()) {
            validationInfo = new ValidationInfoSignDocResponse();
        }

        return new SignaturesSignDocResponse(DocumentWithSignature, allSignaturesObjects, null, validationInfo);
    }
}
