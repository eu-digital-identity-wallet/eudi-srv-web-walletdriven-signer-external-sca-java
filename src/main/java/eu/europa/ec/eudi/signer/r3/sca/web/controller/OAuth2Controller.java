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

import eu.europa.ec.eudi.signer.r3.sca.model.OAuth2Service;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.oauth2.CredentialAuthorizationResponse;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.oauth2.CredentialAuthorizationRequest;
import eu.europa.ec.eudi.signer.r3.sca.model.CredentialsService;
import eu.europa.ec.eudi.signer.r3.sca.model.SignatureService;
import java.util.Date;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping(value = "/credential")
public class OAuth2Controller {
    private final Logger logger = LoggerFactory.getLogger(OAuth2Controller.class);

    private final CredentialsService credentialsService;
    private final SignatureService signatureService;
    private final OAuth2Service oAuth2Service;

    public OAuth2Controller(@Autowired CredentialsService credentialsService, @Autowired SignatureService signatureService,
                            @Autowired OAuth2Service oAuth2Service){
        this.credentialsService = credentialsService;
        this.signatureService = signatureService;
        this.oAuth2Service = oAuth2Service;
    }

    @GetMapping(value = "/authorize", produces = "application/json")
    public CredentialAuthorizationResponse credentialAuthorization(
          @RequestHeader (name="Authorization") String authorizationBearerHeader,
          @RequestBody CredentialAuthorizationRequest credentialAuthorization){
		logger.info("Request received for credential authorization: {}", credentialAuthorization);

        Date date = new Date();
        logger.info("Requested received at {}", date.getTime());

        try {
            CredentialsService.CertificateResponse certificates =
                  this.credentialsService.getCertificateAndChainAndCommonSource(
                        credentialAuthorization.getResourceServerUrl(),
                        credentialAuthorization.getCredentialID(),
                        authorizationBearerHeader);
            logger.info("Retrieved all the required certificates.");

            List<String> hashes = this.signatureService.calculateHashValue(credentialAuthorization.getDocuments(),
                  certificates.getCertificate(), certificates.getCertificateChain(),
                  credentialAuthorization.getHashAlgorithmOID(), date, certificates.getTsaCommonSource());
            String hash = String.join(",", hashes);
            logger.info("Calculated the value of the hashes to sign.");

            return this.oAuth2Service.getOAuth2Authorize(credentialAuthorization, hash, date, authorizationBearerHeader);
        } catch (Exception e){
            logger.error(e.getMessage());
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_response");
        }
    }
}
