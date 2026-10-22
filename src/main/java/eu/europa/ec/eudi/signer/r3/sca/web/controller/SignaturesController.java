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

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import eu.europa.ec.eudi.signer.r3.sca.exception.ExternalSCAException.DocumentSignatureCountMismatchException;
import eu.europa.ec.eudi.signer.r3.sca.model.credential.CredentialsService;
import eu.europa.ec.eudi.signer.r3.sca.model.signature.SignatureService;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.SignedDocumentRequest;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.calculateHash.CalculateHashRequest;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.calculateHash.CalculateHashResponse;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.qtsp.signDoc.DocumentsSignDocRequest;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.qtsp.signDoc.SignaturesSignDocResponse;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import jakarta.validation.Valid;

@RestController
@RequestMapping(value = "/signatures")
public class SignaturesController {
    private final Logger logger = LoggerFactory.getLogger(SignaturesController.class);
    private final SignatureService signatureService;
    private final CredentialsService credentialsService;

    public SignaturesController(@Autowired CredentialsService credentialsService, @Autowired SignatureService signatureService){
        this.credentialsService = credentialsService;
        this.signatureService = signatureService;
    }

    // Calculates base64-encoded hashes of the provided documents.
    // Input includes:
    //   - List of documents with optional per-document configuration
    //   - End-entity certificate and optional certificate chain
    //   - Hash algorithm OID
    // Returns:
    //   - Base64-encoded hashes of the documents
    //   - Timestamp (as a long) when the hashes were created
    @Operation(description = "Calculates base64-encoded hashes values to be signed of given documents using a specified certificate, certificate chain and hash algorithm.")
    @ApiResponses(value = {
          @ApiResponse(responseCode = "200", description = "Hashes calculated successfully", content = @Content(mediaType = "application/json",
                schema = @Schema(implementation = CalculateHashResponse.class))),
          @ApiResponse(responseCode = "400", description = "Bad request. Possible causes: invalid request body," +
                " unsupported hash algorithm OID, invalid hash algorithm OID, invalid base64-encoded end-entity certificate," +
                " or invalid certificates in the base64-encoded certificate chain.", content = @Content),
    })
    @io.swagger.v3.oas.annotations.parameters.RequestBody(description = "JSON object containing required fields: documents (list), endEntityCertificate (string), hashAlgorithmOID (string).", required = true)
    @PostMapping(value="/calculate_hash", consumes = "application/json", produces = "application/json")
    public CalculateHashResponse calculateHash(@Valid @RequestBody CalculateHashRequest calculateHashRequestBody) throws Exception {
        logger.info("Request received at signatures/calculate_hash");
        logger.debug("Request body: {}", calculateHashRequestBody);

        String hashAlgorithmOID = calculateHashRequestBody.getHashAlgorithmOID();
        this.signatureService.validateHashAlgorithmOID(hashAlgorithmOID);

        List<DocumentsSignDocRequest> documents = calculateHashRequestBody.getDocuments();
        logger.debug("Documents received: {} items", documents.size());

        X509Certificate certificate = this.credentialsService.base64DecodeCertificate(calculateHashRequestBody.getEndEntityCertificate());
        List<X509Certificate> certificateChain = new ArrayList<>();
        for(String c: calculateHashRequestBody.getCertificateChain()){
            certificateChain.add(this.credentialsService.base64DecodeCertificate(c));
        }
        CommonTrustedCertificateSource certificateSource = this.credentialsService.getCommonTrustedCertificateSource();
        logger.info("Loaded End Entity Certificate, Certificate Chain and Certificate Source.");

        Date date = new Date();
        List<String> hashes = this.signatureService.calculateHashValue(documents, certificate, certificateChain, certificateSource, hashAlgorithmOID, date);
        logger.info("Successfully created list of hashes.");

		return new CalculateHashResponse(hashes, date.getTime());
    }

     // Endpoints used to retrieve a signed document, given the document, certificate, signature and other required parameters.
    // Input includes:
    //   - List of documents with optional per-document configuration
    //   - End-entity certificate and optional certificate chain
    //   - Hash algorithm OID
    //   - Signature of the hash retrieved in /signatures/calculate_hash
    // Returns
    //   - Signed document
    @Operation(description = "Returns the signed document(s) for the provided document(s). " +
          "Each signature in the request must correspond to the document at the same index. " +
          "Requires the documents, end-entity certificate, signature values, and any other necessary parameters.")
    @ApiResponses(value = {
          @ApiResponse(responseCode = "200", description = "Signed document retrieved successfully", content = @Content(mediaType = "application/json",
                schema = @Schema(implementation = SignaturesSignDocResponse.class))),
          @ApiResponse(responseCode = "400", description = "Bad request. Possible causes: invalid request body," +
                " unsupported hash algorithm OID, invalid hash algorithm OID, invalid base64-encoded end-entity certificate," +
                " or invalid certificates in the base64-encoded certificate chain.", content = @Content),
    })
    @io.swagger.v3.oas.annotations.parameters.RequestBody(description = "JSON object containing required fields: documents (list), endEntityCertificate (string), hashAlgorithmOID (string), date (long) and signature (list).", required = true)
    @PostMapping(value="/obtain_signed_doc", consumes = "application/json", produces = "application/json")
    public SignaturesSignDocResponse obtainSignedDocuments(@Valid @RequestBody SignedDocumentRequest signedDocumentRequestBody) throws Exception {
        logger.info("Request received at signatures/obtain_signed_doc");
        logger.debug("Request body: {}", signedDocumentRequestBody);

        String hashAlgorithmOID = signedDocumentRequestBody.getHashAlgorithmOID();
        this.signatureService.validateHashAlgorithmOID(signedDocumentRequestBody.getHashAlgorithmOID());

        List<DocumentsSignDocRequest> documents = signedDocumentRequestBody.getDocuments();
        logger.debug("Documents received: {} items", documents.size());

        X509Certificate signingCertificate = this.credentialsService.base64DecodeCertificate(signedDocumentRequestBody.getEndEntityCertificate());
        List<X509Certificate> certificateChain = new ArrayList<>();
        for(String c: signedDocumentRequestBody.getCertificateChain()){
            certificateChain.add(this.credentialsService.base64DecodeCertificate(c));
        }
        CommonTrustedCertificateSource certificateSource = this.credentialsService.getCommonTrustedCertificateSource();
        logger.info("Loaded End Entity Certificate, Certificate Chain and Certificate Source.");

        Date date = new Date(signedDocumentRequestBody.getDate());
        boolean returnValidationInfo = signedDocumentRequestBody.isReturnValidationInfo();
        List<String> signatures = signedDocumentRequestBody.getSignatures();

        if(signatures.size() != documents.size()){
            logger.error("The number of signatures received doesn't match the number of documents to signed received. " +
                  "Number of Document: {} & Number of Signatures: {}", documents.size(), signatures.size());
            throw new DocumentSignatureCountMismatchException("The number of signatures received doesn't match the number of documents to signed received.");
        }

        SignaturesSignDocResponse signedDoc = this.signatureService.buildSignedDocument(documents, hashAlgorithmOID, returnValidationInfo, signingCertificate, certificateChain, certificateSource, date, signatures);
        logger.info("Successfully signed document with signature received.");
        return signedDoc;
    }
}
