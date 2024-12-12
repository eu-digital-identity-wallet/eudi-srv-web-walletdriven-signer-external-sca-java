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

package eu.europa.ec.eudi.signer.r3.sca.model.signature;

import eu.europa.ec.eudi.signer.r3.sca.model.QTSPClient;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.signDoc.DocumentsSignDocRequest;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.signDoc.SignaturesSignDocResponse;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.qtsp.signHash.SignaturesSignHashRequest;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.qtsp.signHash.SignaturesSignHashResponse;
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

            if(document.getConformance_level().equals("Ades-B-LTA") || document.getConformance_level().equals("Ades-B-LT")){
                for (X509Certificate cert : certificateChain) {
                    certificateSource.addCertificate(new CertificateToken(cert));
                }
            }

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


    public SignaturesSignDocResponse handleDocumentsSignDocRequest(
          String resourceServerUrl, String authorizationHeader, List<DocumentsSignDocRequest> documents, List<String> hashes,
          String credentialID, X509Certificate certificate, List<X509Certificate> certificateChain,
          CommonTrustedCertificateSource certificateSource, String signAlgo, String hashAlgorithmOID, Date date) throws Exception {

        SignaturesSignHashRequest signHashRequest = new SignaturesSignHashRequest();
        signHashRequest.setCredentialID(credentialID);
        signHashRequest.setSAD(null);
        signHashRequest.setHashes(hashes);
        signHashRequest.setHashAlgorithmOID(hashAlgorithmOID);
        signHashRequest.setSignAlgo(signAlgo);
        signHashRequest.setSignAlgoParams(null);
        signHashRequest.setOperationMode("S");
        signHashRequest.setValidity_period(-1);
        signHashRequest.setResponse_uri(null);

        SignaturesSignHashResponse signHashResponse = qtspClient.requestSignHash(resourceServerUrl, authorizationHeader, signHashRequest);
        List<String> allSignaturesObjects = signHashResponse.getSignatures();

        return buildSignedDocument(documents, hashAlgorithmOID, false, certificate, certificateChain, date, certificateSource, allSignaturesObjects);
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

            if(document.getConformance_level().equals("Ades-B-LTA") || document.getConformance_level().equals("Ades-B-LT")){
                for (X509Certificate cert : certificateChain) {
                    certificateSource.addCertificate(new CertificateToken(cert));
                }
            }

			SignatureDocumentForm signatureDocumentForm = getSignatureForm(document, digestAlgorithm, encryptionAlgorithm, certificate, date, certificateSource, certificateChain);
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


    private SignatureDocumentForm getSignatureForm(
          DocumentsSignDocRequest document, DigestAlgorithm digestAlgorithm, EncryptionAlgorithm encryptionAlgorithm,
          X509Certificate certificate, Date date, CommonTrustedCertificateSource certificateSource, List<X509Certificate> certificateChain){

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
