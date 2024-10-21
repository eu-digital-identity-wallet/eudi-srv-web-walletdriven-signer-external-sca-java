package eu.europa.ec.eudi.signer.r3.sca.model;

import eu.europa.ec.eudi.signer.r3.sca.web.dto.oauth2.CredentialAuthorizationResponse;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.credentialsInfo.CredentialsInfoRequest;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.credentialsInfo.CredentialsInfoResponse;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.oauth2.OAuth2AuthorizeRequest;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.signHash.SignaturesSignHashRequest;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.signHash.SignaturesSignHashResponse;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Optional;

import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.json.JSONObject;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

@Service
public class QTSPClient {
    public CredentialsInfoResponse requestCredentialInfo(String url, CredentialsInfoRequest credentialsInfoRequest, String authorizationBearerHeader){
        WebClient webClient = WebClient.builder()
              .baseUrl(url)
              .defaultCookie("cookieKey", "cookieValue")
              .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
              .build();

        Mono<CredentialsInfoResponse> signHashResponse = webClient.post()
              .uri("/csc/v2/credentials/info")
              .bodyValue(credentialsInfoRequest)
              .header("Authorization", authorizationBearerHeader)

              .exchangeToMono(response -> {
                  if (response.statusCode().equals(HttpStatus.OK)) {
                      return response.bodyToMono(CredentialsInfoResponse.class);
                  } else {
                      System.out.println(response.statusCode().value());
                      return Mono.error(new Exception("Exception"));
                  }
              });

        return signHashResponse.block();
    }

    public SignaturesSignHashResponse requestSignHash(String url, SignaturesSignHashRequest signHashRequest, String authorizationBearerHeader) {
        System.out.println("url: "+url);
        System.out.println("body: "+signHashRequest.toString());
        System.out.println("header: "+authorizationBearerHeader);

        WebClient webClient = WebClient.builder()
                .baseUrl(url)
                .defaultCookie("cookieKey", "cookieValue")
                .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .build();

        Mono<SignaturesSignHashResponse> signHashResponse = webClient.post()
                .uri("/csc/v2/signatures/signHash")
                .bodyValue(signHashRequest)
                .header("Authorization", authorizationBearerHeader)
                .exchangeToMono(response -> {
                    if (response.statusCode().equals(HttpStatus.OK)) {
                        return response.bodyToMono(SignaturesSignHashResponse.class);
                    } else {
                        return Mono.error(new Exception("Exception"));
                    }
                });

        return signHashResponse.block();
    }

    public CredentialAuthorizationResponse requestOAuth2Authorize(String url, OAuth2AuthorizeRequest authorizeRequest, String authorizationBearerHeader) throws Exception {
        try(CloseableHttpClient httpClient = HttpClientBuilder.create().disableRedirectHandling().build()) {
            UriComponentsBuilder uriBuilder = UriComponentsBuilder
                  .fromUriString(url)
                  .pathSegment("oauth2")
                  .pathSegment("authorize");

            uriBuilder
                  .queryParam("response_type", "code")
                  .queryParam("client_id", authorizeRequest.getClient_id())
                  .queryParamIfPresent("redirect_uri", Optional.ofNullable(authorizeRequest.getRedirect_uri()))
                  .queryParamIfPresent("scope", Optional.ofNullable(authorizeRequest.getScope()))
                  .queryParam("code_challenge", Optional.ofNullable(authorizeRequest.getCode_challenge()))
                  .queryParamIfPresent("code_challenge_method", Optional.ofNullable(authorizeRequest.getCode_challenge_method()))
                  .queryParamIfPresent("state", Optional.ofNullable(authorizeRequest.getState()))
                  .queryParamIfPresent("lang", Optional.ofNullable(authorizeRequest.getLang()))
                  .queryParamIfPresent("description", Optional.ofNullable(authorizeRequest.getDescription()))
                  .queryParamIfPresent("account_token", Optional.ofNullable(authorizeRequest.getAccount_token()))
                  .queryParamIfPresent("clientData", Optional.ofNullable(authorizeRequest.getClientData()))
                  .queryParamIfPresent("authorization_details", Optional.ofNullable(authorizeRequest.getAuthorization_details()))
                  .queryParamIfPresent("credentialID", Optional.ofNullable(authorizeRequest.getCredentialID()))
                  .queryParamIfPresent("signatureQualifier", Optional.ofNullable(authorizeRequest.getSignatureQualifier()))
                  .queryParamIfPresent("numSignatures", Optional.ofNullable(authorizeRequest.getNumSignatures()))
                  .queryParamIfPresent("hashes", Optional.ofNullable(authorizeRequest.getHashes()))
                  .queryParamIfPresent("hashAlgorithmOID", Optional.ofNullable(authorizeRequest.getHashAlgorithmOID()));

            String uri = uriBuilder.build().toString();
            HttpGet request = new HttpGet(uri);
            HttpResponse response = httpClient.execute(request);
            System.out.println(response.getStatusLine().getStatusCode());

            if(response.getStatusLine().getStatusCode() == 302) {
                String location = response.getLastHeader("Location").getValue();
                System.out.println("Location: " + location);
                String cookie = response.getLastHeader("Set-Cookie").getValue();
                System.out.println("Cookie: " + cookie);
                return new CredentialAuthorizationResponse(location, cookie);
            }

            return null;
        }
    }

    public JSONObject requestOAuth2Token(String urlBase, String code, String clientId, String redirectUri, String authorizationHeader) throws Exception{
        String uriEndpoint = urlBase+"/oauth2/token";
        URIBuilder uriBuilder = new URIBuilder(uriEndpoint);
        uriBuilder.setParameter("grant_type", "authorization_code");
        uriBuilder.setParameter("code", code);
        uriBuilder.setParameter("client_id", clientId);
        uriBuilder.setParameter("redirect_uri", redirectUri);
        uriBuilder.setParameter("code_verifier",  "root");
        String url = uriBuilder.build().toString();

        try(CloseableHttpClient httpClient2 = HttpClientBuilder.create().build()) {
            HttpPost followRequest = new HttpPost(url);
            followRequest.setHeader(org.apache.http.HttpHeaders.AUTHORIZATION, authorizationHeader);

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

			return new JSONObject(responseString);
        }
    }
}
