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
import eu.europa.ec.eudi.signer.r3.sca.web.dto.signDoc.DocumentsSignDocRequest;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.signDoc.SignaturesSignDocRequest;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.signDoc.SignaturesSignDocResponse;
import eu.europa.ec.eudi.signer.r3.sca.model.CredentialsService;
import eu.europa.ec.eudi.signer.r3.sca.model.SignatureService;
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
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping(value = "/signatures")
public class SignaturesController {
    private final Logger logger = LogManager.getLogger(SignaturesController.class);

    private final SignatureService signatureService;
    private final CredentialsService credentialsService;

    public SignaturesController(@Autowired CredentialsService credentialsService,
                                @Autowired SignatureService signatureService){
        this.credentialsService = credentialsService;
        this.signatureService = signatureService;
    }

    @PostMapping(value = "/signDoc", consumes = "application/json", produces = "application/json")
    public SignaturesSignDocResponse signDoc(
          @RequestBody SignaturesSignDocRequest signDocRequest,
          @RequestHeader (name="Authorization") String authorizationBearerHeader) {
        logger.info("Request received for signing document: {}", signDocRequest);

        if (signDocRequest.getCredentialID() == null) {
            logger.error("The credentialId should be specified in the Request Body.");
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                  "invalid_response: the credentialId should be specified.");
        }

        if (authorizationBearerHeader == null) {
            logger.error("The current solution expects the credential token to be sent in the Authorization Header.");
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                  "invalid_response: the authorization header with credential authorization should be present.");
        }

        if(signDocRequest.getDocuments() == null){
            logger.error("The documents to be signed should be sent in the Http Request Body.");
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                  "invalid_response: the documents to be signed should be sent in the request.");
        }

        if(signDocRequest.getSignature_date() == 0){
            logger.error("The date when the credential authorization was requested should be sent in the Http Request Body.");
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                  "invalid_response: the date when the credential authorization was requested should be sent in the request.");
        }

        try {
            Date date = new Date(signDocRequest.getSignature_date());

            CredentialsService.CertificateResponse certificates =
                  this.credentialsService.getCertificateAndChainAndCommonSource(
                  signDocRequest.getRequest_uri(),
                  signDocRequest.getCredentialID(),
                  authorizationBearerHeader);
            logger.info("Retrieved all the required certificates.");

            SignaturesSignDocResponse signaturesResponse = this.signatureService.handleDocumentsSignDocRequest(
                  signDocRequest, authorizationBearerHeader, certificates.getCertificate(),
                  certificates.getCertificateChain(), certificates.getSignAlgo(), date, certificates.getTsaCommonSource());
            logger.info("Obtained the documents signed.");

            return signaturesResponse;
        } catch (Exception e) {
            logger.error(e.getMessage());
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_response");
        }
    }

    @PostMapping(value="/calculate_hash", consumes = "application/json", produces = "application/json")
    public CalculateHashResponse calculateHash(@RequestBody CalculateHashRequest requestDTO) throws Exception{

        List<DocumentsSignDocRequest> documents = requestDTO.getDocuments();
        if(requestDTO.getDocuments() == null){
            logger.error("The documents to be signed should be sent in the Http Request Body.");
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                  "invalid_response: the documents to be signed should be sent in the request.");
        }

        if(requestDTO.getEndEntityCertificate() == null){
            logger.error("The certificate is missing from the request.");
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_response: the certificate parameter is missing.");
        }
        X509Certificate certificate = this.credentialsService.base64DecodeCertificate(requestDTO.getEndEntityCertificate());
        logger.info("Loaded signing certificate.");

        List<X509Certificate> certificateChain = new ArrayList<>();
        for(String c: requestDTO.getCertificateChain()){
            certificateChain.add(this.credentialsService.base64DecodeCertificate(c));
        }
        logger.info("Loaded certificate chain.");

        String hashAlgorithmOID = requestDTO.getHashAlgorithmOID();
        if(hashAlgorithmOID == null){
            logger.error("The digest/hash algorithm oid parameter is missing.");
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_response: the hash algorithm oid is missing.");
        }

        Date date = new Date();

        CommonTrustedCertificateSource certificateSource = this.credentialsService.getCommonTrustedCertificateSource();
        logger.info("Loaded certificate source.");

        List<String> hashes = this.signatureService.calculateHashValue(documents, certificate, certificateChain, hashAlgorithmOID, date, certificateSource);
        logger.info("Created list of hashes.");

		return new CalculateHashResponse(hashes, date.getTime());
    }

    @PostMapping(value="/obtain_signed_doc", consumes = "application/json", produces = "application/json")
    public SignaturesSignDocResponse obtainSignedDocuments(@RequestBody SignedDocumentRequest requestDTO) throws Exception{
        List<DocumentsSignDocRequest> documents = requestDTO.getDocuments();
        if(documents == null || documents.isEmpty()){
            logger.error("The documents to be signed should be sent in the Http Request Body.");
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                  "invalid_response: the documents to be signed should be sent in the request.");
        }

        String hashAlgorithmOID = requestDTO.getHashAlgorithmOID();
        if(hashAlgorithmOID == null){
            logger.error("The digest/hash algorithm oid parameter is missing.");
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_response: the hash algorithm oid is missing.");
        }

        boolean returnValidationInfo = requestDTO.isReturnValidationInfo();

        if(requestDTO.getEndEntityCertificate() == null){
            logger.error("The certificate is missing from the request.");
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_response: the certificate parameter is missing.");
        }
        X509Certificate signingCertificate = this.credentialsService.base64DecodeCertificate(requestDTO.getEndEntityCertificate());

        List<X509Certificate> certificateChain = new ArrayList<>();
        for(String c: requestDTO.getCertificateChain()){
            certificateChain.add(this.credentialsService.base64DecodeCertificate(c));
        }
        logger.info("Loaded certificate chain.");

        if(requestDTO.getDate() == 0){
            logger.error("The date parameter is missing.");
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_response: the date parameter is missing.");
        }
        Date date = new Date(requestDTO.getDate());

        CommonTrustedCertificateSource certificateSource = this.credentialsService.getCommonTrustedCertificateSource();
        logger.info("Loaded the certificate source");

        List<String> signatures = requestDTO.getSignatures();
        if(signatures == null || signatures.isEmpty()){
            logger.error("The signature parameter is missing.");
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_response: the signature parameter is missing.");
        }
        if(signatures.size() != documents.size()){
            logger.error("The number of signatures received doesn't match the number of documents to signed received.");
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_response: " +
                  "the number of signatures received doesn't match the number of documents to signed received.");
        }
        return this.signatureService.buildSignedDocument(documents, hashAlgorithmOID, returnValidationInfo, signingCertificate,
              certificateChain, date, certificateSource, signatures);
    }
}
