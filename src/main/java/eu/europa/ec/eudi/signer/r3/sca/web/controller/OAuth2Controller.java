package eu.europa.ec.eudi.signer.r3.sca.web.controller;

import eu.europa.ec.eudi.signer.r3.sca.web.dto.AuthResponseTemporary;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.CredentialAuthorizationRequest;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.OAuth2AuthorizeRequest;
import eu.europa.ec.eudi.signer.r3.sca.model.QtspClient;
import eu.europa.ec.eudi.signer.r3.sca.model.CredentialsService;
import eu.europa.ec.eudi.signer.r3.sca.model.SignatureService;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.http.Header;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.sql.CommonDataSource;
import java.io.*;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Properties;

@RestController
@RequestMapping(value = "/credential")
public class OAuth2Controller {

    private final QtspClient qtspClient;
    private final CredentialsService credentialsService;
    private final SignatureService signatureService;

    public OAuth2Controller(@Autowired QtspClient qtspClient, @Autowired CredentialsService credentialsService,
                            @Autowired SignatureService signatureService) throws Exception{
        this.qtspClient = qtspClient;
        this.credentialsService = credentialsService;
        this.signatureService = signatureService;
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

        saveCertificateToPem(certificateResponse.getCertificate(), "cert_0.pem");
        int i = 1;
        for (X509Certificate c: certificateResponse.getCertificateChain()){
            saveCertificateToPem(c, "cert_"+i+".pem");
            i++;
        }

        CommonTrustedCertificateSource certificateSource = this.credentialsService.getCommonTrustedCertificateSource(certificateResponse.getCertificateChain());

        List<String> hashes = this.signatureService.calculateHashValue(credentialAuthorization.getDocuments(), certificateResponse.getCertificate(), certificateResponse.getCertificateChain(), credentialAuthorization.getHashAlgorithmOID(), date, certificateSource);
        String hash = String.join(",", hashes);

        // generate code_challenge, code_challenge_method, code_verifier
        String code_challenge = generateNonce("root");

        OAuth2AuthorizeRequest authorizeRequest = new OAuth2AuthorizeRequest();
        authorizeRequest.setClient_id("sca-client");
        authorizeRequest.setRedirect_uri("http://localhost:8086/credential/oauth/login/code");
        authorizeRequest.setScope("credential");
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

    private static String getBasicAuthenticationHeader(String username, String password) {
        String valueToEncode = username + ":" + password;
        return "Basic " + Base64.getEncoder().encodeToString(valueToEncode.getBytes());
    }

    @GetMapping(value="/oauth/login/code", produces="application/json")
    public String credential_authorization_code(HttpServletRequest request) throws Exception{
        System.out.println("Login Code: -----------------------------");

        String code_verifier = "root";

        if(request.getParameter("code") != null){
            String code = request.getParameter("code");
            System.out.println("Code: "+code);

            String url = "http://localhost:8084/oauth2/token?" +
                  "grant_type=authorization_code&" +
                  "code=" + code + "&" +
                  "client_id=sca-client&"+
                  "redirect_uri=http%3A%2F%2Flocalhost:8086%2Fcredential%2Foauth%2Flogin%2Fcode&" +
                  "code_verifier="+code_verifier;
            System.out.println("Url: "+url);

            String authorizationHeader = getBasicAuthenticationHeader("sca-client", "somesecret1");
            System.out.println("Authorization Header: "+authorizationHeader);
            String new_session_id = request.getHeader("Set-Cookie");

            try(CloseableHttpClient httpClient2 = HttpClientBuilder.create().build()) {
                HttpPost followRequest = new HttpPost(url);
                followRequest.setHeader(HttpHeaders.AUTHORIZATION, authorizationHeader);
                followRequest.setHeader("Cookie", new_session_id);

                System.out.println(followRequest.getHeaders(HttpHeaders.AUTHORIZATION)[0].getValue());
                HttpResponse followResponse = httpClient2.execute(followRequest);

                System.out.println(followResponse.getStatusLine().getStatusCode());

                for(Header h: followResponse.getAllHeaders()){
                    System.out.println(h.getName()+": "+h.getValue());
                }

                InputStream is = followResponse.getEntity().getContent();
                BufferedReader reader = new BufferedReader(new InputStreamReader(is));
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    sb.append(line).append("\n");
                }
                is.close();
                String responseString = sb.toString();

                JSONObject json = new JSONObject(responseString);
                System.out.println(json);

                return responseString;
            }
        }
        return null;
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
