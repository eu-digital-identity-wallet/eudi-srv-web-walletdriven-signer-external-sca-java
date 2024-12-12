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

import eu.europa.ec.eudi.signer.r3.sca.model.credential.CredentialsService;
import eu.europa.ec.eudi.signer.r3.sca.model.oauth2.OAuth2Service;
import eu.europa.ec.eudi.signer.r3.sca.model.SessionState;
import eu.europa.ec.eudi.signer.r3.sca.model.signature.SignatureService;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.qtsp.oauth2.CredentialAuthorizationRequest;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.signDoc.SignaturesSignDocResponse;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.net.http.HttpResponse;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import org.springframework.security.core.session.SessionRegistry;

@Controller
@RequestMapping(value = "/signatures")
public class CallbackController {
    private static final Logger logger = LoggerFactory.getLogger(CallbackController.class);
    private final OAuth2Service oAuth2Service;
    private final SignatureService signatureService;
    private final CredentialsService credentialsService;
    private final SessionRegistry sessionRegistry;

    public CallbackController(@Autowired OAuth2Service oAuth2Service, @Autowired SignatureService signatureService,
                              @Autowired CredentialsService credentialsService, @Autowired SessionRegistry sessionRegistry) {
        this.oAuth2Service = oAuth2Service;
        this.signatureService = signatureService;
        this.credentialsService = credentialsService;
        this.sessionRegistry = sessionRegistry;
    }

    // the resource server url
    // the credential id to use
    // the sad
    // the document to signed
    // hash algorithm oid
    @PostMapping(value="/start")
    public void signatureFlow(
          @RequestHeader(name="Authorization") String authorizationBearerHeader,
          @RequestBody CredentialAuthorizationRequest credentialAuthorization,
          HttpSession session, HttpServletResponse response) throws IOException {
        logger.debug("Request received for signature flow: {}.", credentialAuthorization);
        
        Date date = new Date();
        logger.debug("Requested received at {}.", date.getTime());

        CredentialsService.CertificateResponse certificates;
        try {
            certificates = this.credentialsService.getCertificateAndChainAndCommonSource(
                  credentialAuthorization.getResourceServerUrl(), credentialAuthorization.getCredentialID(), authorizationBearerHeader);
        }
        catch (Exception e){
            logger.error(e.getMessage());
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "There was an error obtaining the certificate. Please try again.");
            return;
        }
        logger.info("Retrieved all the required certificates.");

        X509Certificate certificate = certificates.getCertificate();
        logger.info("Loaded signing certificate.");

		List<X509Certificate> certificateChain = certificates.getCertificateChain();
        logger.info("Loaded certificate chain.");

        CommonTrustedCertificateSource certificateSource = certificates.getTsaCommonSource();
        logger.info("Loaded certificate source.");

        List<String> hashes;
        String hash;
        try {
            hashes = this.signatureService.calculateHashValue(credentialAuthorization.getDocuments(), certificate,
                  certificateChain, credentialAuthorization.getHashAlgorithmOID(), date, certificateSource);

            hash = String.join(";", hashes.subList(0, hashes.size() - 1))
                  + (hashes.size() > 1 ? ";" : "")
                  + hashes.get(hashes.size() - 1);
        }
        catch (Exception e){
            logger.error(e.getMessage());
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "There was an error calculating the document digest value. Please try again.");
            return;
        }
        logger.info("Obtained the list of hashes.");

        SecureRandom prng = new SecureRandom();
        String code_verifier = String.valueOf(prng.nextInt());
        logger.info("Obtained the code verifier value.");

        String numSignatures = Integer.toString(hashes.size());
        String location;
        try {
            location = this.oAuth2Service.getOAuth2AuthorizeAuthenticationLocation(
                  credentialAuthorization.getAuthorizationServerUrl(), credentialAuthorization.getCredentialID(),
                  numSignatures, hash, credentialAuthorization.getHashAlgorithmOID(), session.getId(), code_verifier);
        }
        catch (Exception e){
            logger.error(e.getMessage());
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "There was an error trying to obtain the credential authorization. Please try again.");
            return;
        }

        SessionState sessionState = new SessionState();
        sessionState.setDate(date.getTime());
        sessionState.setCredentialID(credentialAuthorization.getCredentialID());
        sessionState.setEndEntityCertificate(certificate);
        sessionState.setCertificateChain(certificateChain);
        sessionState.setSignAlgo(certificates.getSignAlgo().get(0));
        sessionState.setDocuments(credentialAuthorization.getDocuments());
        sessionState.setHash(hashes);
        sessionState.setHashAlgorithmOID(credentialAuthorization.getHashAlgorithmOID());
        sessionState.setCodeVerifier(code_verifier);
        sessionState.setAuthorizationServerUrl(credentialAuthorization.getAuthorizationServerUrl());
        sessionState.setResourceServerUrl(credentialAuthorization.getResourceServerUrl());
        sessionState.setRedirectUri(credentialAuthorization.getRedirectUri());

        session.setAttribute("signatureState", sessionState);
        this.sessionRegistry.registerNewSession(session.getId(), session);

        response.sendRedirect(location);
    }

    @GetMapping(value="/callback")
    public String credential_authorization_code(@RequestParam("code") String code, @RequestParam("state") String state, Model model, HttpServletResponse response) throws IOException {
        SessionInformation sessionInformation = this.sessionRegistry.getSessionInformation(state);
        HttpSession session = (HttpSession) sessionInformation.getPrincipal();
        SessionState sessionState = (SessionState) session.getAttribute("signatureState");

        String access_token;
        try {
            access_token = this.oAuth2Service.getOAuth2AccessToken(sessionState.getAuthorizationServerUrl(), code, sessionState.getCodeVerifier());
        }
        catch (Exception e){
            logger.error(e.getMessage());
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "There was an error trying to obtain the credential authorization. Please try again.");
            return null;
        }
        logger.info("Obtained Access Token with scope Credential.");

        CommonTrustedCertificateSource certificateSource = this.credentialsService.getCommonTrustedCertificateSource();
        logger.info("Loaded certificate source.");

        Date date = new Date(sessionState.getDate());

        SignaturesSignDocResponse signaturesResponse;
        try {
            signaturesResponse = this.signatureService.handleDocumentsSignDocRequest(
                  sessionState.getResourceServerUrl(), access_token, sessionState.getDocuments(), sessionState.getHash(),
                  sessionState.getCredentialID(), sessionState.getEndEntityCertificate(), sessionState.getCertificateChain(),
                  certificateSource, sessionState.getSignAlgo(), sessionState.getHashAlgorithmOID(), date);
            logger.info("Obtained the documents signed.");
        }
        catch (Exception e){
            logger.error(e.getMessage());
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "There was an error trying to obtain the signed document. Please try again.");
            return null;
        }

        String signed_document_base64 = signaturesResponse.getDocumentWithSignature().get(0);
        String redirect_uri = sessionState.getRedirectUri();

        model.addAttribute("url",  redirect_uri);
        model.addAttribute("body", signed_document_base64);
        return "successful_authentication";
    }
}
