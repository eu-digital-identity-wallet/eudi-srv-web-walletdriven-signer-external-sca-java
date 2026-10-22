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

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import eu.europa.ec.eudi.signer.r3.sca.config.TimestampAuthorityConfig;
import eu.europa.ec.eudi.signer.r3.sca.exception.ExternalSCAException.DocumentSignDocParameterInvalidException;
import eu.europa.ec.eudi.signer.r3.sca.exception.ExternalSCAException.HashAlgorithmOIDInvalidException;
import eu.europa.ec.eudi.signer.r3.sca.exception.ExternalSCAException.UnsupportedSignatureFormatException;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.qtsp.signDoc.DocumentsSignDocRequest;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.qtsp.signDoc.SignaturesSignDocResponse;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.qtsp.signDoc.ValidationInfoSignDocResponse;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;

@Service
public class SignatureService {
    private static final Logger logger = LoggerFactory.getLogger(SignatureService.class);
    private final DSSService dssClient;
    private final TimestampAuthorityConfig timestampAuthorityConfig;

    public SignatureService(@Autowired DSSService dssClient, @Autowired TimestampAuthorityConfig timestampAuthorityConfig) {
        this.dssClient = dssClient;
        this.timestampAuthorityConfig = timestampAuthorityConfig;
    }

    public List<String> calculateHashValue(List<DocumentsSignDocRequest> documents, X509Certificate certificate, List<X509Certificate> certificateChain,
                                           CommonTrustedCertificateSource certificateSource, String hashAlgorithmOID, Date date) throws DocumentSignDocParameterInvalidException, UnsupportedSignatureFormatException {

        List<String> hashes = new ArrayList<>();
        for (DocumentsSignDocRequest document : documents) {
            logger.info("Payload Received:{ Conformance Level:{}, Signature Format:{}, Hash Algorithm OID:{}, Signature Packaging:{}, Type of Container:{} }",
                  document.getConformance_level(), document.getSignature_format(), hashAlgorithmOID, document.getSigned_envelope_property(), document.getContainer());

            CommonTrustedCertificateSource certificateSourceCopy = new CommonTrustedCertificateSource();
            certificateSource.getCertificates().forEach(certificateSourceCopy::addCertificate);
            if(document.getConformance_level().equals("Ades-B-LTA") || document.getConformance_level().equals("Ades-B-LT")){
                for (X509Certificate cert : certificateChain) {
                    certificateSourceCopy.addCertificate(new CertificateToken(cert));
                }
            }

            byte[] dataToBeSigned = dssClient.getDigestOfDataToBeSigned(document, certificate, certificateSourceCopy,
                  certificateChain, hashAlgorithmOID, date);
            if (dataToBeSigned == null) continue;

            logger.info("Successfully created digest of data to be signed of a document.");

            String dataToBeSignedStringEncoded = Base64.getEncoder().encodeToString(dataToBeSigned);
            hashes.add(dataToBeSignedStringEncoded);
        }

        logger.info("Successfully created 'DataToBeSigned' for {} documents.", documents.size());
        return hashes;
    }

    public SignaturesSignDocResponse buildSignedDocument(
          List<DocumentsSignDocRequest> documents, String hashAlgorithmOID, boolean returnValidationInfo,
          X509Certificate certificate, List<X509Certificate> certificateChain, CommonTrustedCertificateSource certificateSource,
          Date date, List<String> signatureObjects) throws DocumentSignDocParameterInvalidException, UnsupportedSignatureFormatException {

        List<String> DocumentWithSignature = new ArrayList<>();

        for (int i = 0; i < documents.size(); i++) {
            DocumentsSignDocRequest document = documents.get(i);
            String signatureValue = signatureObjects.get(i);

            CommonTrustedCertificateSource certificateSourceCopy = new CommonTrustedCertificateSource();
            certificateSource.getCertificates().forEach(certificateSourceCopy::addCertificate);
            if(document.getConformance_level().equals("Ades-B-LTA") || document.getConformance_level().equals("Ades-B-LT")){
                for (X509Certificate cert : certificateChain) {
                    certificateSourceCopy.addCertificate(new CertificateToken(cert));
                }
            }

            DSSDocument docSigned = dssClient.signDocument(document, hashAlgorithmOID, certificate, date, certificateSourceCopy, certificateChain, signatureValue);
            logger.info("Document successfully signed.");
            String signedDocumentString = getSignedDocumentString(document, docSigned);
            DocumentWithSignature.add(signedDocumentString);
        }

        ValidationInfoSignDocResponse validationInfo = null;
        if (returnValidationInfo) validationInfo = new ValidationInfoSignDocResponse();

        logger.info("Successfully signed {} documents", documents.size());
        return new SignaturesSignDocResponse(DocumentWithSignature, signatureObjects, null, validationInfo);
    }

    public void validateHashAlgorithmOID(String hashAlgorithmOID) throws HashAlgorithmOIDInvalidException {
        // validate if the hashAlgorithmOID is supported by the TSA
        if (!timestampAuthorityConfig.getSupportedDigestAlgorithm().contains(hashAlgorithmOID)){
            String message = String.format("The hash algorithm OID '%s' is not supported by the TSA. Supported OIDs: %s",
                  hashAlgorithmOID, timestampAuthorityConfig.getSupportedDigestAlgorithm());
            logger.error(message);
            throw new HashAlgorithmOIDInvalidException(message);
        }

        // validate if the hashAlgorithmOID is a supported digestAlgorithm
        try {
            DSSService.getDigestAlgorithmFromOID(hashAlgorithmOID);
        } catch (Exception e){
            String message = String.format("Failed to retrieve a digest algorithm for hashAlgorithmOID '%s'. Error: %s",
                  hashAlgorithmOID, e.getMessage());
            logger.error(message, e);
            throw new HashAlgorithmOIDInvalidException(String.format("The hashAlgorithmOID '%s' is invalid or unrecognized.", hashAlgorithmOID));
        }
        logger.debug("Hash Algorithm OID: {}", hashAlgorithmOID);
        logger.info("Successfully validated the hashAlgorithmOID received");
    }

    private String getSignedDocumentString(DocumentsSignDocRequest document, DSSDocument docSigned) {
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

        InMemoryDocument signedDocument = new InMemoryDocument(DSSUtils.toByteArray(docSigned), docSigned.getName(), docSigned.getMimeType());
        return Base64.getEncoder().encodeToString(signedDocument.getBytes());
    }
}
