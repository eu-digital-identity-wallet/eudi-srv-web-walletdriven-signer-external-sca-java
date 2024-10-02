package eu.europa.ec.eudi.signer.r3.sca.web.controller;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Base64;

import eu.europa.ec.eudi.signer.r3.sca.config.OAuthClientConfig;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class CallbackController {

    private final OAuthClientConfig oAuthClientConfig;

    public CallbackController(@Autowired OAuthClientConfig oAuthClientConfig) {
        this.oAuthClientConfig = oAuthClientConfig;
    }

    @GetMapping(value="/credential/oauth/login/code")
    public String credential_authorization_code(@RequestParam("code") String code, Model model) throws Exception {
        URIBuilder uriBuilder = new URIBuilder("http://localhost:8084/oauth2/token");
        uriBuilder.setParameter("grant_type", "authorization_code");
        uriBuilder.setParameter("code", code);
        uriBuilder.setParameter("client_id", this.oAuthClientConfig.getClientId());
        uriBuilder.setParameter("redirect_uri", this.oAuthClientConfig.getRedirectUri());
        uriBuilder.setParameter("code_verifier",  "root");

        String url = uriBuilder.build().toString();
        System.out.println("URI: "+ url);

        String authorizationHeader = getBasicAuthenticationHeader(this.oAuthClientConfig.getClientId(), this.oAuthClientConfig.getClientSecret());
        try(CloseableHttpClient httpClient2 = HttpClientBuilder.create().build()) {
            HttpPost followRequest = new HttpPost(url);
            followRequest.setHeader(HttpHeaders.AUTHORIZATION, authorizationHeader);

            HttpResponse followResponse = httpClient2.execute(followRequest);

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

            model.addAttribute("body", json.toString());
            model.addAttribute("url", "http://127.0.0.1:5000/oauth/credential/login/code");
            return "successful_authentication";
        }
    }

    private static String getBasicAuthenticationHeader(String username, String password) {
        String valueToEncode = username + ":" + password;
        return "Basic " + Base64.getEncoder().encodeToString(valueToEncode.getBytes());
    }


}
