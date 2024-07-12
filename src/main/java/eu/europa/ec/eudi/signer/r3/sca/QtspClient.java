package eu.europa.ec.eudi.signer.r3.sca;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import eu.europa.ec.eudi.signer.r3.sca.DTO.SignaturesSignHashRequest;
import eu.europa.ec.eudi.signer.r3.sca.DTO.SignaturesSignHashResponse;
import reactor.core.publisher.Mono;

@Service
public class QtspClient {

    /*
     * public void requestInfo(String url) {
     * WebClient webClient = WebClient.builder()
     * .baseUrl(url)
     * .defaultCookie("cookieKey", "cookieValue")
     * .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
     * .build();
     * 
     * webClient.post()
     * .uri("/csc/v2/info")
     * .bodyValue();
     * // .header("");
     * }
     * 
     * public void requestOAuth2Authorize(String url) {
     * WebClient webClient = WebClient.builder()
     * .baseUrl(url)
     * .defaultCookie("cookieKey", "cookieValue")
     * .build();
     * 
     * webClient.get()
     * .uri("/csc/v2/oauth2/authorize")
     * .bodyValue();
     * // .header("");
     * }
     * 
     * public void requestCredentialsList(String url) {
     * WebClient webClient = WebClient.builder()
     * .baseUrl(url)
     * .defaultCookie("cookieKey", "cookieValue")
     * .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
     * .build();
     * 
     * webClient.post()
     * .uri("/csc/v2/credentials/list")
     * .bodyValue();
     * // .header("");
     * }
     * 
     * public void requestCredentialsInfo(String url) {
     * WebClient webClient = WebClient.builder()
     * .baseUrl(url)
     * .defaultCookie("cookieKey", "cookieValue")
     * .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
     * .build();
     * 
     * webClient.post()
     * .uri("/csc/v2/credentials/info")
     * .bodyValue();
     * // .header("");
     * }
     * 
     * 
     */

    public SignaturesSignHashResponse requestSignHash(String url, SignaturesSignHashRequest signHashRequest)
            throws Exception {
        // TODO: missing headers!

        System.out.println(signHashRequest.toString());

        WebClient webClient = WebClient.builder()
                .baseUrl(url)
                .defaultCookie("cookieKey", "cookieValue")
                .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .build();

        Mono<SignaturesSignHashResponse> signHashResponse = webClient.post()
                .uri("/csc/v2/signatures/signHash")
                .bodyValue(signHashRequest)
                .header("Authorization", "")
                .exchangeToMono(response -> {
                    if (response.statusCode().equals(HttpStatus.OK)) {
                        return response.bodyToMono(SignaturesSignHashResponse.class);
                    } else {
                        return Mono.error(new Exception("Exception"));
                    }
                });

        return signHashResponse.block();
    }
}
