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
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.sql.CommonDataSource;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
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
    private final CertificateToken TSACertificateToken;


    public OAuth2Controller(@Autowired QtspClient qtspClient,
                            @Autowired CredentialsService credentialsService,
                            @Autowired SignatureService signatureService) throws Exception{
        this.qtspClient = qtspClient;
        this.credentialsService = credentialsService;
        this.signatureService = signatureService;

        Properties properties = new Properties();
        InputStream configStream = getClass().getClassLoader().getResourceAsStream("config.properties");
        if (configStream == null) {
            throw new Exception("Arquivo config.properties não encontrado!");
        }
        properties.load(configStream);

        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        String certificateStringPath = properties.getProperty("TrustedCertificates");
        if (certificateStringPath == null || certificateStringPath.isEmpty()) {
            throw new Exception("Trusted Certificate Path not found in configuration file.");
        }
        FileInputStream certInput= new FileInputStream(certificateStringPath);
        X509Certificate TSACertificate = (X509Certificate) certFactory.generateCertificate(certInput);
        this.TSACertificateToken = new CertificateToken(TSACertificate);
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
        CredentialsService.CertificateResponse certificateResponse = this.credentialsService.getCertificateAndCertificateChain(credentialAuthorization.getResourceServerUrl(), credentialAuthorization.getCredentialID(), authorizationBearerHeader);

        Date date = new Date();
        CommonTrustedCertificateSource certificateSource = new CommonTrustedCertificateSource();
        certificateSource.addCertificate(this.TSACertificateToken);
        for(X509Certificate cert: certificateResponse.getCertificateChain()){
            certificateSource.addCertificate(new CertificateToken(cert));
        }


        // calculate hash
        List<String> hashes = this.signatureService.calculateHashValue(credentialAuthorization.getDocuments(), certificateResponse.getCertificate(), certificateResponse.getCertificateChain(), credentialAuthorization.getHashAlgorithmOID(), date, certificateSource);
        for(String s: hashes){
            System.out.println("Oauth2: "+ s);
        }

        String hash = String.join(",", hashes);
        System.out.println("hash: "+hash);

        // generate code_challenge, code_challenge_method, code_verifier
        String code_challenge = generateNonce("root");

        OAuth2AuthorizeRequest authorizeRequest = new OAuth2AuthorizeRequest();
        authorizeRequest.setClient_id("sca-client");
        authorizeRequest.setRedirect_uri("http://localhost:8082/credential/oauth/login/code");
        authorizeRequest.setScope("credential");
        authorizeRequest.setCode_challenge(code_challenge);
        authorizeRequest.setCode_challenge_method("S256");
        authorizeRequest.setLang("pt-PT");
        authorizeRequest.setState("12345678");
        authorizeRequest.setCredentialID(URLEncoder.encode(credentialAuthorization.getCredentialID(), StandardCharsets.UTF_8));
        authorizeRequest.setNumSignatures(credentialAuthorization.getNumSignatures());
        authorizeRequest.setHashes(hash);
        authorizeRequest.setHashAlgorithmOID(credentialAuthorization.getHashAlgorithmOID());

        AuthResponseTemporary responseTemporary = this.qtspClient.requestOAuth2Authorize(credentialAuthorization.getAuthorizationServerUrl(), authorizeRequest, authorizationBearerHeader);
        System.out.println(date.getTime());
        responseTemporary.setSignature_date(date.getTime());
        System.out.println("-----------------------------");
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

            String url = "http://localhost:9000/oauth2/token?" +
                  "grant_type=authorization_code&" +
                  "code=" + code + "&" +
                  "client_id=sca-client&"+
                  "redirect_uri=http%3A%2F%2Flocalhost%3A8082%2Fcredential%2Foauth%2Flogin%2Fcode&" +
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
}
