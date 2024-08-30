package eu.europa.ec.eudi.signer.r3.sca.Controllers;

import eu.europa.ec.eudi.signer.r3.sca.DTO.AuthRequestTemporary;
import eu.europa.ec.eudi.signer.r3.sca.DTO.OAuth2AuthorizeRequest;
import eu.europa.ec.eudi.signer.r3.sca.QtspClient;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.http.Header;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

@RestController
@RequestMapping(value = "/credential")
public class OAuth2Controller {

    private final QtspClient qtspClient;

    public OAuth2Controller(@Autowired QtspClient qtspClient){
        this.qtspClient = qtspClient;
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

    @GetMapping(value = "/authorize")
    public void credential_authorization() throws Exception{
        System.out.println("Authorize: -----------------------------");
        String qtspUrl = "http://localhost:9000";

        // calculate hash

        // given some credential

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
        authorizeRequest.setCredentialID(URLEncoder.encode("cred1", StandardCharsets.UTF_8));
        authorizeRequest.setNumSignatures(Integer.toString(1));
        authorizeRequest.setHashes("some_document_hash");
        authorizeRequest.setHashAlgorithmOID("2.16.840.1.101.3.4.2.1");

        this.qtspClient.requestOAuth2Authorize(qtspUrl, authorizeRequest);
        System.out.println("-----------------------------");
    }

    @GetMapping("/temporary")
    public void temporary(@RequestBody AuthRequestTemporary authRequest) throws Exception{
        System.out.println("Temporary: -----------------------------");

        System.out.println("URL: " + authRequest.getUrl());
        System.out.println("Cookie: " + authRequest.getCookie());

        String location_redirect = null;
        String new_session_id = null;

        // Get localhost:9000 after auth
        try(CloseableHttpClient httpClient = HttpClientBuilder.create().disableRedirectHandling().build()) {

            HttpGet followRequest = new HttpGet(authRequest.getUrl());
            followRequest.setHeader("Cookie", authRequest.getCookie());
            HttpResponse followResponse = httpClient.execute(followRequest);

            if(followResponse.getStatusLine().getStatusCode() == 302) {
                location_redirect = followResponse.getLastHeader("Location").getValue();
                System.out.println("Location: "+location_redirect);
                new_session_id = followResponse.getLastHeader("Set-Cookie").getElements()[0].toString();
                System.out.println("Cookie: "+new_session_id);
            }
        }

        if ( location_redirect==null || new_session_id == null )
            return;

        System.out.println("-----------------------------");

        // Get /oauth2/authorize after oid4vp
        try(CloseableHttpClient httpClient2 = HttpClientBuilder.create().build()) {
            HttpGet followRequest = new HttpGet(location_redirect);
            followRequest.setHeader("Cookie", new_session_id);
            HttpResponse followResponse = httpClient2.execute(followRequest);
            // System.out.println(followResponse.getStatusLine().getStatusCode());
        }
    }


    private static String getBasicAuthenticationHeader(String username, String password) {
        String valueToEncode = username + ":" + password;
        return "Basic " + Base64.getEncoder().encodeToString(valueToEncode.getBytes());
    }

    @GetMapping(value="/oauth/login/code")
    public void credential_authorization_code(HttpServletRequest request) throws Exception{
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

            String authorizationHeader = getBasicAuthenticationHeader("sca-client", "secret");
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
            }

        }

    }
}
