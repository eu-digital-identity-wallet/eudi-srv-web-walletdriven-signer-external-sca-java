package eu.europa.ec.eudi.signer.r3.sca.model;

import eu.europa.ec.eudi.signer.r3.sca.web.dto.signDoc.DocumentsSignDocRequest;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.signDoc.SignaturesSignDocRequest;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.signDoc.SignaturesSignDocResponse;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.signHash.SignaturesSignHashRequest;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.signHash.SignaturesSignHashResponse;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.signDoc.ValidationInfoSignDocResponse;
import eu.europa.esig.dss.enumerations.*;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
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

    public SignatureService(@Autowired QTSPClient qtspClient, @Autowired DSSService dssClient) {
        this.qtspClient = qtspClient;
        this.dssClient = dssClient;
    }

    public List<String> calculateHashValue(List<DocumentsSignDocRequest> documents, X509Certificate certificate,
										   List<X509Certificate> certificateChain, String hashAlgorithmOID, Date date,
										   CommonTrustedCertificateSource certificateSource) throws Exception {

		DigestAlgorithm digestAlgorithm = DSSService.checkDigestAlgorithm(hashAlgorithmOID);
		EncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithm.forName(certificate.getPublicKey().getAlgorithm());

        List<String> hashes = new ArrayList<>();
        for (DocumentsSignDocRequest document : documents) {
            fileLogger.info("Session_id:{},Payload Received:{ Document Hash:{}, conformance_level:{},Signature Format:{}, Hash Algorithm OID:{}, Signature Packaging:{}, Type of Container:{}}", RequestContextHolder.currentRequestAttributes().getSessionId(), digestAlgorithm, document.getConformance_level(), document.getSignature_format(), hashAlgorithmOID, document.getSigned_envelope_property(), document.getContainer());

            /*if(document.getConformance_level().equals("Ades-B-LTA") || document.getConformance_level().equals("Ades-B-LT")){
                System.out.println("here1");
                for (X509Certificate cert : certificateChain) {
                    certificateSource.addCertificate(new CertificateToken(cert));
                }
            }
            System.out.println(certificateSource.getCertificates().size());*/

			SignatureDocumentForm signatureDocumentForm = getSignatureForm(document, digestAlgorithm, encryptionAlgorithm,
					certificate, date, certificateSource, certificateChain);

			byte[] dataToBeSigned = dssClient.getDigestOfDataToBeSigned(signatureDocumentForm);
            if (dataToBeSigned == null) continue;

            String dataToBeSignedStringEncoded = Base64.getEncoder().encodeToString(dataToBeSigned);
            String dataToBeSignedURLEncoded = URLEncoder.encode(dataToBeSignedStringEncoded, StandardCharsets.UTF_8);
            hashes.add(dataToBeSignedURLEncoded);
        }
        fileLogger.info("Session_id:{},DataToBeSigned successfully created", RequestContextHolder.currentRequestAttributes().getSessionId());
        return hashes;
    }


    public SignaturesSignDocResponse handleDocumentsSignDocRequest(SignaturesSignDocRequest signDocRequest, String authorizationBearerHeader,
																   X509Certificate certificate, List<X509Certificate> certificateChain,
																   List<String> signAlgo, Date date, CommonTrustedCertificateSource certificateSource) throws Exception {
        List<String> hashes = calculateHashValue(signDocRequest.getDocuments(), certificate, certificateChain, signDocRequest.getHashAlgorithmOID(), date, certificateSource);

        SignaturesSignHashRequest signHashRequest = new SignaturesSignHashRequest(signDocRequest.getCredentialID(), null,
                hashes, signDocRequest.getHashAlgorithmOID(), signAlgo.get(0), null, "S",
                -1, null, signDocRequest.getClientData());
        fileLogger.info("Session_id:{},HTTP Request to QTSP.", RequestContextHolder.currentRequestAttributes().getSessionId());
        SignaturesSignHashResponse signHashResponse = qtspClient.requestSignHash(signDocRequest.getRequest_uri(), signHashRequest, authorizationBearerHeader);
        List<String> allSignaturesObjects = signHashResponse.getSignatures();
        fileLogger.info("Session_id:{},HTTP Response received.", RequestContextHolder.currentRequestAttributes().getSessionId());

        if (signHashResponse.getSignatures().size() != signDocRequest.getDocuments().size())
            return new SignaturesSignDocResponse();

		DigestAlgorithm digestAlgorithm = DSSService.checkDigestAlgorithm(signDocRequest.getHashAlgorithmOID());
		EncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithm.forName(certificate.getPublicKey().getAlgorithm());

        List<String> DocumentWithSignature = new ArrayList<>();
        for (int i = 0; i < signDocRequest.getDocuments().size(); i++) {
            DocumentsSignDocRequest document = signDocRequest.getDocuments().get(i);
            String signatureValue = signHashResponse.getSignatures().get(i);

            SignatureDocumentForm signatureDocumentForm = getSignatureForm(document, digestAlgorithm, encryptionAlgorithm,
					certificate, date, certificateSource, certificateChain);

            signatureDocumentForm.setSignatureValue(Base64.getDecoder().decode(signatureValue));

            DSSDocument docSigned = dssClient.signDocument(signatureDocumentForm);
            fileLogger.info("Session_id:{},Document successfully signed.", RequestContextHolder.currentRequestAttributes().getSessionId());
            String signedDocumentString = getSignedDocumentString(document, docSigned);
            DocumentWithSignature.add(signedDocumentString);
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

        if (signatureObjects.size() != documents.size()) return new SignaturesSignDocResponse();

		DigestAlgorithm digestAlgorithm = DSSService.checkDigestAlgorithm(hashAlgorithmOID);
		EncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithm.forName(certificate.getPublicKey().getAlgorithm());

        List<String> DocumentWithSignature = new ArrayList<>();
        for (int i = 0; i < documents.size(); i++) {
            DocumentsSignDocRequest document = documents.get(i);
            String signatureValue = signatureObjects.get(i);

            /*if(document.getConformance_level().equals("Ades-B-LTA") || document.getConformance_level().equals("Ades-B-LT")){
                System.out.println("here2");
                for (X509Certificate cert : certificateChain) {
                    certificateSource.addCertificate(new CertificateToken(cert));
                }
            }
            System.out.println(certificateSource.getCertificates().size());*/

			SignatureDocumentForm signatureDocumentForm = getSignatureForm(document, digestAlgorithm, encryptionAlgorithm,
					certificate, date, certificateSource, certificateChain);
            signatureDocumentForm.setSignatureValue(Base64.getDecoder().decode(signatureValue));

            DSSDocument docSigned = dssClient.signDocument(signatureDocumentForm);
            fileLogger.info("Session_id:{},Document successfully signed.", RequestContextHolder.currentRequestAttributes().getSessionId());
            String signedDocumentString = getSignedDocumentString(document, docSigned);
            DocumentWithSignature.add(signedDocumentString);
        }

        ValidationInfoSignDocResponse validationInfo = null;
        if (returnValidationInfo) validationInfo = new ValidationInfoSignDocResponse();

        return new SignaturesSignDocResponse(DocumentWithSignature, signatureObjects, null, validationInfo);
    }


    private SignatureDocumentForm getSignatureForm(DocumentsSignDocRequest document, DigestAlgorithm digestAlgorithm,
                                                   EncryptionAlgorithm encryptionAlgorithm, X509Certificate certificate,
                                                   Date date, CommonTrustedCertificateSource certificateSource,
                                                   List<X509Certificate> certificateChain){

        DSSDocument dssDocument = dssClient.loadDssDocument(document.getDocument());

        SignatureLevel signatureLevel = DSSService.checkConformance_level(document.getConformance_level(), document.getSignature_format());
        SignaturePackaging signaturePackaging = DSSService.checkEnvProps(document.getSigned_envelope_property());
        ASiCContainerType asicContainerType = DSSService.checkASiCContainerType(document.getContainer());
        SignatureForm signatureForm = DSSService.checkSignForm(document.getSignature_format());

        SignatureDocumentForm signatureDocumentForm = new SignatureDocumentForm();
        signatureDocumentForm.setDocumentToSign(dssDocument);
        signatureDocumentForm.setSignaturePackaging(signaturePackaging);
        signatureDocumentForm.setContainerType(asicContainerType);
        signatureDocumentForm.setSignatureLevel(signatureLevel);
        signatureDocumentForm.setDigestAlgorithm(digestAlgorithm);
        signatureDocumentForm.setSignatureForm(signatureForm);
        signatureDocumentForm.setCertificate(certificate);
        signatureDocumentForm.setDate(date);
        signatureDocumentForm.setTrustedCertificates(certificateSource);
        signatureDocumentForm.setSignatureForm(signatureForm);
        signatureDocumentForm.setCertChain(certificateChain);
        signatureDocumentForm.setEncryptionAlgorithm(encryptionAlgorithm);

        return signatureDocumentForm;
    }


    private String getSignedDocumentString(DocumentsSignDocRequest document, DSSDocument docSigned) throws Exception{
        try {
            if (document.getContainer().equals("ASiC-E")) {
                if (document.getSignature_format().equals("C") || document.getSignature_format().equals("X")) {
                    docSigned.setMimeType(MimeType.fromMimeTypeString("application/vnd.etsi.asic-e+zip"));
                }
            } else if (document.getContainer().equals("ASiC-S")) {
                if (document.getSignature_format().equals("C") || document.getSignature_format().equals("X")) {
                    docSigned.setMimeType(MimeType.fromMimeTypeString("application/vnd.etsi.asic-s+zip"));
                }
            } else if (document.getSignature_format().equals("J")) {
                docSigned.setMimeType(MimeType.fromMimeTypeString("application/jose"));
            } else if (document.getSignature_format().equals("X")) {
                docSigned.setMimeType(MimeType.fromMimeTypeString("text/xml"));
            } else {
                docSigned.setMimeType(MimeType.fromMimeTypeString("application/pdf"));
            }
        } catch (Exception e) {
            fileLogger.error("invalid request: {}", e.getMessage());
            throw e;
        }
        return Base64.getEncoder().encodeToString(docSigned.openStream().readAllBytes());
    }
}
