package eu.europa.ec.eudi.signer.r3.sca.model;

import eu.europa.ec.eudi.signer.r3.sca.web.dto.signDoc.DocumentsSignDocRequest;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.signDoc.SignaturesSignDocRequest;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.signDoc.SignaturesSignDocResponse;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.signHash.SignaturesSignHashRequest;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.signHash.SignaturesSignHashResponse;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.signDoc.ValidationInfoSignDocResponse;
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
    private final QTSPClient qtspClient;
    private final DSSService dssClient;

    public SignatureService(@Autowired QTSPClient qtspClient, @Autowired DSSService dssClient){
        this.qtspClient = qtspClient;
        this.dssClient = dssClient;
    }

    public List<String> calculateHashValue(List<DocumentsSignDocRequest> documents, X509Certificate signingCertificate, List<X509Certificate> certificateChain, String hashAlgorithmOID, Date date, CommonTrustedCertificateSource certificateSource) throws Exception{
        List<String> hashes = new ArrayList<>();
        for (DocumentsSignDocRequest document : documents) {
            DSSDocument dssDocument = dssClient.loadDssDocument(document.getDocument());

            SignatureLevel aux_sign_level = DSSService.checkConformance_level(document.getConformance_level(), document.getSignature_format());
            DigestAlgorithm aux_digest_alg = DSSService.checkDigestAlgorithm(hashAlgorithmOID);
            EncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithm.forName(signingCertificate.getPublicKey().getAlgorithm());
            SignaturePackaging aux_sign_pack = DSSService.checkEnvProps(document.getSigned_envelope_property());
            ASiCContainerType aux_asic_ContainerType = DSSService.checkASiCContainerType(document.getContainer());
            SignatureForm signatureForm = DSSService.checkSignForm(document.getSignature_format());

            fileLogger.info("Session_id:"+ RequestContextHolder.currentRequestAttributes().getSessionId() +",Payload Received:{ Document Hash:"+  aux_digest_alg +", conformance_level:" +document.getConformance_level()+ ","+
                  "Signature Format:"+ document.getSignature_format() + ", Hash Algorithm OID:"+ hashAlgorithmOID + ", Signature Packaging:"+ document.getSigned_envelope_property() + ", Type of Container:"+ document.getContainer() + "}");

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
            signatureDocumentForm.setCertChain(certificateChain);
            signatureDocumentForm.setEncryptionAlgorithm(encryptionAlgorithm);

            byte[] dataToBeSigned = dssClient.DataToBeSignedData(signatureDocumentForm);
            fileLogger.info("Session_id:"+ RequestContextHolder.currentRequestAttributes().getSessionId() +",DataToBeSigned successfully created");

            if (dataToBeSigned == null) continue;

            String dataToBeSignedStringEncoded = Base64.getEncoder().encodeToString(dataToBeSigned);
            String dataToBeSignedURLEncoded = URLEncoder.encode(dataToBeSignedStringEncoded, StandardCharsets.UTF_8);
            hashes.add(dataToBeSignedURLEncoded);
        }
        return hashes;
    }

    public SignaturesSignDocResponse handleDocumentsSignDocRequest(SignaturesSignDocRequest signDocRequest, String authorizationBearerHeader, X509Certificate certificate, List<X509Certificate> certificateChain, List<String> signAlgo, Date date, CommonTrustedCertificateSource certificateSource) throws Exception {
        List<String> hashes = calculateHashValue(signDocRequest.getDocuments(), certificate, certificateChain, signDocRequest.getHashAlgorithmOID(), date, certificateSource);

        SignaturesSignHashRequest signHashRequest = new SignaturesSignHashRequest(signDocRequest.getCredentialID(),null,
              hashes, signDocRequest.getHashAlgorithmOID(), signAlgo.get(0), null, "S",
              -1, null, signDocRequest.getClientData());
        fileLogger.info("Session_id:"+ RequestContextHolder.currentRequestAttributes().getSessionId() +",HTTP Request to QTSP.");
        SignaturesSignHashResponse signHashResponse = qtspClient.requestSignHash(signDocRequest.getRequest_uri(), signHashRequest, authorizationBearerHeader);
        List<String> allSignaturesObjects = signHashResponse.getSignatures();
        fileLogger.info("Session_id:"+ RequestContextHolder.currentRequestAttributes().getSessionId() +",HTTP Response received.");

        if(signHashResponse.getSignatures().size() != signDocRequest.getDocuments().size()) return new SignaturesSignDocResponse();

        List<String> DocumentWithSignature = new ArrayList<>();
        for(int i = 0; i < signDocRequest.getDocuments().size(); i++){
            DocumentsSignDocRequest document = signDocRequest.getDocuments().get(i);
            String signatureValue = signHashResponse.getSignatures().get(i);

            DSSDocument dssDocument = dssClient.loadDssDocument(document.getDocument());

            SignatureLevel aux_sign_level = DSSService.checkConformance_level(document.getConformance_level(), document.getSignature_format());
            DigestAlgorithm aux_digest_alg = DSSService.checkDigestAlgorithm(signDocRequest.getHashAlgorithmOID());
            EncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithm.forName(certificate.getPublicKey().getAlgorithm());
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
            signatureDocumentForm.setCertChain(certificateChain);
            signatureDocumentForm.setEncryptionAlgorithm(encryptionAlgorithm);
            signatureDocumentForm.setSignatureValue(Base64.getDecoder().decode(signatureValue));

            DSSDocument docSigned = dssClient.signDocument(signatureDocumentForm);
            fileLogger.info("Session_id:"+ RequestContextHolder.currentRequestAttributes().getSessionId() +",Document successfully signed.");

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
                    DocumentWithSignature.add(Base64.getEncoder().encodeToString(docSigned.openStream().readAllBytes()));
                }
            } catch (Exception e) {
                fileLogger.error("invalid request: "+ e.getMessage());
                throw e;
            }
        }

        ValidationInfoSignDocResponse validationInfo = null;
        if (signDocRequest.getReturnValidationInfo()) {
            validationInfo = new ValidationInfoSignDocResponse();
        }

        return new SignaturesSignDocResponse(DocumentWithSignature, allSignaturesObjects, null, validationInfo);
    }


    public SignaturesSignDocResponse buildSignedDocument(
          List<DocumentsSignDocRequest> documents, String hashAlgorithmOID, boolean returnValidationInfo,
          X509Certificate certificate, List<X509Certificate> certificateChain, Date date,
          CommonTrustedCertificateSource certificateSource, List<String> signatureObjects) throws Exception {

        if(signatureObjects.size() != documents.size()) return new SignaturesSignDocResponse();

        List<String> DocumentWithSignature = new ArrayList<>();
        for(int i = 0; i < documents.size(); i++){
            DocumentsSignDocRequest document = documents.get(i);
            String signatureValue = signatureObjects.get(i);

            DSSDocument dssDocument = dssClient.loadDssDocument(document.getDocument());

            SignatureLevel aux_sign_level = DSSService.checkConformance_level(document.getConformance_level(), document.getSignature_format());
            DigestAlgorithm aux_digest_alg = DSSService.checkDigestAlgorithm(hashAlgorithmOID);
            EncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithm.forName(certificate.getPublicKey().getAlgorithm());
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
            signatureDocumentForm.setCertChain(certificateChain);
            signatureDocumentForm.setEncryptionAlgorithm(encryptionAlgorithm);
            signatureDocumentForm.setSignatureValue(Base64.getDecoder().decode(signatureValue));

            DSSDocument docSigned = dssClient.signDocument(signatureDocumentForm);
            fileLogger.info("Session_id:"+ RequestContextHolder.currentRequestAttributes().getSessionId() +",Document successfully signed.");

            try {
                if (document.getContainer().equals("ASiC-E")) {
                    if (document.getSignature_format().equals("C") || document.getSignature_format().equals("X")) {
                        docSigned.setMimeType(MimeType.fromMimeTypeString("application/vnd.etsi.asic-e+zip"));
                    }
                }
                else if (document.getContainer().equals("ASiC-S")) {
                    if (document.getSignature_format().equals("C") || document.getSignature_format().equals("X")) {
                        docSigned.setMimeType(MimeType.fromMimeTypeString("application/vnd.etsi.asic-s+zip"));
                    }
                }
                else if (document.getSignature_format().equals("J")) {
                    docSigned.setMimeType(MimeType.fromMimeTypeString("application/jose"));
                }
                else if (document.getSignature_format().equals("X")) {
                    docSigned.setMimeType(MimeType.fromMimeTypeString("text/xml"));
                }
                else {
                    docSigned.setMimeType(MimeType.fromMimeTypeString("application/pdf"));
                }
                DocumentWithSignature.add(Base64.getEncoder().encodeToString(docSigned.openStream().readAllBytes()));
            } catch (Exception e) {
                fileLogger.error("invalid request: "+ e.getMessage());
                throw e;
            }
        }

        ValidationInfoSignDocResponse validationInfo = null;
        if (returnValidationInfo) {
            validationInfo = new ValidationInfoSignDocResponse();
        }

        return new SignaturesSignDocResponse(DocumentWithSignature, signatureObjects, null, validationInfo);
    }


}
