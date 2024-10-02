package eu.europa.ec.eudi.signer.r3.sca.web.controller;

import eu.europa.ec.eudi.signer.r3.sca.config.OAuthClientConfig;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.AuthResponseTemporary;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.CredentialAuthorizationRequest;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.OAuth2AuthorizeRequest;
import eu.europa.ec.eudi.signer.r3.sca.model.QtspClient;
import eu.europa.ec.eudi.signer.r3.sca.model.CredentialsService;
import eu.europa.ec.eudi.signer.r3.sca.model.SignatureService;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.io.*;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.List;

@RestController
@RequestMapping(value = "/credential")
public class OAuth2Controller {

    private final QtspClient qtspClient;
    private final CredentialsService credentialsService;
    private final SignatureService signatureService;
    private final OAuthClientConfig oAuthClientConfig;

    public OAuth2Controller(@Autowired QtspClient qtspClient, @Autowired CredentialsService credentialsService,
                            @Autowired SignatureService signatureService, @Autowired OAuthClientConfig oAuthClientConfig) throws Exception{
        this.qtspClient = qtspClient;
        this.credentialsService = credentialsService;
        this.signatureService = signatureService;
        this.oAuthClientConfig = oAuthClientConfig;
    }

    private String generateNonce(String root) throws Exception{
        SecureRandom prng = new SecureRandom();
        String randomNum = String.valueOf(prng.nextInt());
        System.out.println("Code_Verifier: "+ root);
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] result = sha.digest(root.getBytes());
        String code_challenge = Base64.getUrlEncoder().encodeToString(result);
        System.out.println("Code_Challenge: "+code_challenge);
        return code_challenge;
    }

    @GetMapping(value = "/authorize", produces = "application/json")
    public AuthResponseTemporary credential_authorization(
          @RequestBody CredentialAuthorizationRequest credentialAuthorization,
          @RequestHeader (name="Authorization") String authorizationBearerHeader) throws Exception{
        System.out.println("authorization: "+authorizationBearerHeader);
        System.out.println("credential authorization request: "+credentialAuthorization);

        Date date = new Date();
        CredentialsService.CertificateResponse certificateResponse = this.credentialsService.getCertificateAndCertificateChain(credentialAuthorization.getResourceServerUrl(), credentialAuthorization.getCredentialID(), authorizationBearerHeader);
        CommonTrustedCertificateSource certificateSource = this.credentialsService.getCommonTrustedCertificateSource(certificateResponse.getCertificateChain());

        List<String> hashes = this.signatureService.calculateHashValue(credentialAuthorization.getDocuments(), certificateResponse.getCertificate(), certificateResponse.getCertificateChain(), credentialAuthorization.getHashAlgorithmOID(), date, certificateSource);
        String hash = String.join(",", hashes);

        // generate code_challenge, code_challenge_method, code_verifier
        String code_challenge = generateNonce("root");

        OAuth2AuthorizeRequest authorizeRequest = new OAuth2AuthorizeRequest();
        authorizeRequest.setClient_id(this.oAuthClientConfig.getClientId());
        authorizeRequest.setRedirect_uri(this.oAuthClientConfig.getRedirectUri());
        authorizeRequest.setScope(this.oAuthClientConfig.getScope());
        authorizeRequest.setCode_challenge(code_challenge);
        authorizeRequest.setCode_challenge_method("S256");
        authorizeRequest.setLang("pt-PT");
        authorizeRequest.setState("12345678");
        authorizeRequest.setCredentialID(URLEncoder.encode(credentialAuthorization.getCredentialID(), StandardCharsets.UTF_8));
        authorizeRequest.setNumSignatures(credentialAuthorization.getNumSignatures());
        authorizeRequest.setHashes(hash);
        authorizeRequest.setHashAlgorithmOID(credentialAuthorization.getHashAlgorithmOID());

        /*
        JSONArray documentDigests = new JSONArray();
        for(String h: hashes){
            JSONObject documentDigest = new JSONObject();
            documentDigest.put("hash", h);
            documentDigest.put("label", "This is some document hash");
            documentDigests.put(documentDigest);
        }

        JSONObject authorization_details = new JSONObject();
        authorization_details.put("type", "credential");
        authorization_details.put("credentialID", URLEncoder.encode(credentialAuthorization.getCredentialID(), StandardCharsets.UTF_8));
        authorization_details.put("documentDigests", documentDigests);
        authorization_details.put("hashAlgorithmOID", credentialAuthorization.getHashAlgorithmOID());
        System.out.println(authorization_details);

        OAuth2AuthorizeRequest authorizeRequest = new OAuth2AuthorizeRequest();
        authorizeRequest.setResponse_type("code");
        authorizeRequest.setClient_id("sca-client");
        authorizeRequest.setRedirect_uri("http://localhost:8086/credential/oauth/login/code");
        authorizeRequest.setCode_challenge(code_challenge);
        authorizeRequest.setCode_challenge_method("S256");
        authorizeRequest.setLang("pt-PT");
        authorizeRequest.setState("12345678");
        authorizeRequest.setAuthorization_details(URLEncoder.encode(authorization_details.toString(), StandardCharsets.UTF_8));
        System.out.println(authorizeRequest);*/

        AuthResponseTemporary responseTemporary = this.qtspClient.requestOAuth2Authorize(credentialAuthorization.getAuthorizationServerUrl(), authorizeRequest, authorizationBearerHeader);
        responseTemporary.setSignature_date(date.getTime());
        return responseTemporary;
    }

    public static void saveCertificateToPem(X509Certificate certificate, String filePath) throws IOException, CertificateEncodingException {
        String pemCertificate = convertToPem(certificate);
        try (Writer writer = new FileWriter(filePath)) {
            writer.write(pemCertificate);
        }
    }

    public static String convertToPem(X509Certificate certificate) throws CertificateEncodingException {
        byte[] encodedCert = certificate.getEncoded();
        String base64Cert = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(encodedCert);
        return "-----BEGIN CERTIFICATE-----\n" + base64Cert + "\n-----END CERTIFICATE-----\n";
    }

}
