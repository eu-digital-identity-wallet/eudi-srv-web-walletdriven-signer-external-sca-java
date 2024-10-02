package eu.europa.ec.eudi.signer.r3.sca.model;

import eu.europa.ec.eudi.signer.r3.sca.web.dto.AuthResponseTemporary;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.CredentialsInfo.CredentialsInfoRequest;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.CredentialsInfo.CredentialsInfoResponse;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.OAuth2AuthorizeRequest;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.SignaturesSignHashRequest;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.SignaturesSignHashResponse;
import java.util.Optional;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

@Service
public class QtspClient {

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

    public AuthResponseTemporary requestOAuth2Authorize(String url, OAuth2AuthorizeRequest authorizeRequest, String authorizationBearerHeader) throws Exception {

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
            System.out.println(uri);
            HttpGet request = new HttpGet(uri);
            HttpResponse response = httpClient.execute(request);
            System.out.println(response.getStatusLine().getStatusCode());

            if(response.getStatusLine().getStatusCode() == 302) {
                String location = response.getLastHeader("Location").getValue();
                System.out.println("Location: " + location);
                String cookie = response.getLastHeader("Set-Cookie").getValue();
                System.out.println("Cookie: " + cookie);
                return new AuthResponseTemporary(location, cookie);
            }

            return null;
        }
    }

    public CredentialsInfoResponse requestCredentialInfo(String url, CredentialsInfoRequest credentialsInfoRequest, String authorizationBearerHeader){
        WebClient webClient = WebClient.builder()
              .baseUrl(url)
              .defaultCookie("cookieKey", "cookieValue")
              .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
              .build();

        System.out.println("url: "+url);
        System.out.println("body: "+credentialsInfoRequest);
        System.out.println("header: "+authorizationBearerHeader);

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
}
