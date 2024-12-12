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

package eu.europa.ec.eudi.signer.r3.sca.model;

import eu.europa.ec.eudi.signer.r3.sca.web.dto.qtsp.credentialsInfo.CredentialsInfoRequest;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.qtsp.credentialsInfo.CredentialsInfoResponse;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.qtsp.oauth2.OAuth2AuthorizeRequest;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.qtsp.oauth2.OAuth2TokenRequest;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.qtsp.signHash.SignaturesSignHashRequest;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.qtsp.signHash.SignaturesSignHashResponse;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Optional;

import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

@Service
public class QTSPClient {
    private static final Logger log = LoggerFactory.getLogger(QTSPClient.class);

    public CredentialsInfoResponse requestCredentialInfo(String resourceServerUrl, String authorizationHeader, CredentialsInfoRequest credentialsInfoRequest) throws Exception{
        log.info("Making /credentials/info request to Resource Server {}", resourceServerUrl);
        log.debug("Request Body: {}", credentialsInfoRequest.toString());

		WebClient webClient = WebClient.builder()
			  .baseUrl(resourceServerUrl)
			  .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
			  .build();

		Mono<CredentialsInfoResponse> signHashResponse = webClient.post()
			  .uri("/csc/v2/credentials/info")
			  .bodyValue(credentialsInfoRequest)
			  .header("Authorization", authorizationHeader)
			  .exchangeToMono(response -> {
				  if (response.statusCode().equals(HttpStatus.OK)) {
					  return response.bodyToMono(CredentialsInfoResponse.class);
				  } else {
					  return response.createError();
				  }
			  });
		log.info("Requested Credentials Info.");
		return signHashResponse.onErrorMap(error -> new Exception(error.getMessage())).block();
	}

    public SignaturesSignHashResponse requestSignHash(String resourceServerUrl, String authorizationHeader, SignaturesSignHashRequest signHashRequest) {
        log.info("Making /signatures/signHash request to Resource Server {}", resourceServerUrl);
        log.debug("Request Body: {}", signHashRequest.toString());

        WebClient webClient = WebClient.builder()
                .baseUrl(resourceServerUrl)
                .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .build();

        Mono<SignaturesSignHashResponse> signHashResponse = webClient.post()
                .uri("/csc/v2/signatures/signHash")
                .bodyValue(signHashRequest)
                .header("Authorization", authorizationHeader)
                .exchangeToMono(response -> {
                    if (response.statusCode().equals(HttpStatus.OK)) {
                        return response.bodyToMono(SignaturesSignHashResponse.class);
                    } else {
                        return response.createError();
                    }
                });
        log.info("Requested Sign Hash.");
        return signHashResponse.block();
    }

    public String requestOAuth2Authorize(String authorizeServerUrl, OAuth2AuthorizeRequest authorizeRequest) throws Exception {
        log.info("Making /oauth2/authorize request to Authorization Server {}", authorizeServerUrl);

        try(CloseableHttpClient httpClient = HttpClientBuilder.create().disableRedirectHandling().build()) {
            // {as_url}/oauth2/authorize
            UriComponentsBuilder uriBuilder = UriComponentsBuilder
                  .fromUriString(authorizeServerUrl)
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
            log.info("Request: {}", uri);

            HttpGet request = new HttpGet(uri);
            HttpResponse response = httpClient.execute(request);

            if(response.getStatusLine().getStatusCode() == 302) {
                String location = response.getLastHeader("Location").getValue();
                log.info("Retrieved the authentication url: {}", location);
                return location;
            }

            return null;
        }
    }

    public JSONObject requestOAuth2Token(String authorizeServerUrl, String authorizationHeader, OAuth2TokenRequest tokenRequest) throws Exception{
        try(CloseableHttpClient httpClient2 = HttpClientBuilder.create().build()) {

            // {as_url}/oauth2/authorize
            UriComponentsBuilder uriBuilder = UriComponentsBuilder
                  .fromUriString(authorizeServerUrl)
                  .pathSegment("oauth2")
                  .pathSegment("token");

            uriBuilder
                  .queryParam("grant_type", "authorization_code")
                  .queryParam("code", tokenRequest.getCode())
                  .queryParamIfPresent("refresh_token", Optional.ofNullable(tokenRequest.getRefresh_token()))
                  .queryParam("client_id", tokenRequest.getClient_id())
                  .queryParamIfPresent("client_secret", Optional.ofNullable(tokenRequest.getClient_secret()))
                  .queryParamIfPresent("client_assertion", Optional.ofNullable(tokenRequest.getClient_assertion()))
                  .queryParamIfPresent("client_assertion_type", Optional.ofNullable(tokenRequest.getClient_assertion_type()))
                  .queryParamIfPresent("redirect_uri", Optional.ofNullable(tokenRequest.getRedirect_uri()))
                  .queryParamIfPresent("authorization_details", Optional.ofNullable(tokenRequest.getAuthorization_details()))
                  .queryParam("code_verifier", tokenRequest.getCode_verifier());

            String url = uriBuilder.build().toString();
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
