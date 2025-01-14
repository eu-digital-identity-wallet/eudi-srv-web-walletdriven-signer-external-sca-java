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

package eu.europa.ec.eudi.signer.r3.sca.web.controller;

import eu.europa.ec.eudi.signer.r3.sca.web.dto.calculateHash.CalculateHashRequest;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.calculateHash.CalculateHashResponse;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.qtsp.signDoc.DocumentsSignDocRequest;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.qtsp.signDoc.SignaturesSignDocResponse;
import eu.europa.ec.eudi.signer.r3.sca.model.credential.CredentialsService;
import eu.europa.ec.eudi.signer.r3.sca.model.signature.SignatureService;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.SignedDocumentRequest;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping(value = "/signatures")
public class SignaturesController {
    private final Logger logger = LogManager.getLogger(SignaturesController.class);
    private final SignatureService signatureService;
    private final CredentialsService credentialsService;

    public SignaturesController(@Autowired CredentialsService credentialsService, @Autowired SignatureService signatureService){
        this.credentialsService = credentialsService;
        this.signatureService = signatureService;
    }

    /**
     * Endpoints to calculate the hash of given documents using a specified certificate, certificate chain and hash algorithm.
     * @param calculateHashRequestBody A JSON object containing:
     *                                - a list of documents
     *                                - the certificate and certificate chain
     *                                - hash algorithm OID
     *                                Each document in the list should be accompanied by the configuration of the signed document to be generated
     * @return A JSON object containing:
     *         - the hashes of the documents
     *         - the date (as a long value) indicating when the hash was created
     */
    @PostMapping(value="/calculate_hash", consumes = "application/json", produces = "application/json")
    public CalculateHashResponse calculateHash(@RequestBody CalculateHashRequest calculateHashRequestBody) throws Exception{
        validateCalculateHashRequest(calculateHashRequestBody.getDocuments(), calculateHashRequestBody.getEndEntityCertificate(), calculateHashRequestBody.getHashAlgorithmOID());
        logger.info("Validated that request contains the required values.");

        try {
            this.signatureService.validateSignatureRequest(calculateHashRequestBody.getDocuments(), calculateHashRequestBody.getHashAlgorithmOID());
        } catch (Exception e){
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
        }

        List<DocumentsSignDocRequest> documents = calculateHashRequestBody.getDocuments();
        logger.info("Retrieve document from request.");

        String hashAlgorithmOID = calculateHashRequestBody.getHashAlgorithmOID();
        logger.info("Retrieve hashAlgorithmOID from request.");

        X509Certificate certificate = this.credentialsService.base64DecodeCertificate(calculateHashRequestBody.getEndEntityCertificate());
        logger.info("Loaded signing certificate.");

        List<X509Certificate> certificateChain = new ArrayList<>();
        for(String c: calculateHashRequestBody.getCertificateChain()){
            certificateChain.add(this.credentialsService.base64DecodeCertificate(c));
        }
        logger.info("Loaded certificate chain.");

        CommonTrustedCertificateSource certificateSource = this.credentialsService.getCommonTrustedCertificateSource();
        logger.info("Loaded certificate source.");

        Date date = new Date();

        List<String> hashes = this.signatureService.calculateHashValue(documents, certificate, certificateChain, certificateSource, hashAlgorithmOID, date);
        logger.info("Created list of hashes.");

		return new CalculateHashResponse(hashes, date.getTime());
    }

    private void validateCalculateHashRequest(List<DocumentsSignDocRequest> documents, String endEntityCertificate, String hashAlgorithmOID) throws ResponseStatusException{
        if(documents == null || documents.isEmpty()){
            logger.error("The documents to be signed should be sent in the Http Request Body.");
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                  "invalid_response: the documents to be signed should be sent in the request.");
        }

        if(endEntityCertificate == null){
            logger.error("The certificate is missing from the request.");
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_response: the certificate parameter is missing.");
        }

        if(hashAlgorithmOID == null){
            logger.error("The digest/hash algorithm oid parameter is missing.");
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_response: the hash algorithm oid is missing.");
        }
    }

    /**
     * Endpoints to calculate the hash of given documents using a specified certificate, certificate chain and hash algorithm.
     * @param signedDocumentRequestBody A JSON object containing:
     *                                - a list of documents
     *                                - the certificate and certificate chain
     *                                - hash algorithm OID
     *                                Each document in the list should be accompanied by the configuration of the signed document to be generated
     * @return A JSON object containing:
     *         - the hashes of the documents
     *         - the date (as a long value) indicating when the hash was created
     */
    @PostMapping(value="/obtain_signed_doc", consumes = "application/json", produces = "application/json")
    public SignaturesSignDocResponse obtainSignedDocuments(@RequestBody SignedDocumentRequest signedDocumentRequestBody) throws Exception{
        validateCalculateHashRequest(signedDocumentRequestBody.getDocuments(), signedDocumentRequestBody.getEndEntityCertificate(), signedDocumentRequestBody.getHashAlgorithmOID());

        try {
            this.signatureService.validateSignatureRequest(signedDocumentRequestBody.getDocuments(), signedDocumentRequestBody.getHashAlgorithmOID());
        } catch (Exception e){
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
        }

        List<DocumentsSignDocRequest> documents = signedDocumentRequestBody.getDocuments();
        logger.info("Retrieve document from request.");

        String hashAlgorithmOID = signedDocumentRequestBody.getHashAlgorithmOID();
        logger.info("Retrieve hashAlgorithmOID from request.");

        boolean returnValidationInfo = signedDocumentRequestBody.isReturnValidationInfo();

        X509Certificate signingCertificate = this.credentialsService.base64DecodeCertificate(signedDocumentRequestBody.getEndEntityCertificate());

        List<X509Certificate> certificateChain = new ArrayList<>();
        for(String c: signedDocumentRequestBody.getCertificateChain()){
            certificateChain.add(this.credentialsService.base64DecodeCertificate(c));
        }
        logger.info("Loaded certificate chain.");

        if(signedDocumentRequestBody.getDate() == 0){
            logger.error("The date parameter is missing.");
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_response: the date parameter is missing.");
        }
        Date date = new Date(signedDocumentRequestBody.getDate());

        CommonTrustedCertificateSource certificateSource = this.credentialsService.getCommonTrustedCertificateSource();
        logger.info("Loaded certificate source");

        List<String> signatures = signedDocumentRequestBody.getSignatures();
        if(signatures == null || signatures.isEmpty()){
            logger.error("The signature parameter is missing.");
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_response: the signature parameter is missing.");
        }
        if(signatures.size() != documents.size()){
            logger.error("The number of signatures received doesn't match the number of documents to signed received.");
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_response: " +
                  "the number of signatures received doesn't match the number of documents to signed received.");
        }
        return this.signatureService.buildSignedDocument(documents, hashAlgorithmOID, returnValidationInfo, signingCertificate, certificateChain, certificateSource, date, signatures);
    }
}
