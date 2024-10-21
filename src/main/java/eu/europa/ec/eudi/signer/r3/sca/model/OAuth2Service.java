package eu.europa.ec.eudi.signer.r3.sca.model;

import eu.europa.ec.eudi.signer.r3.sca.config.OAuthClientConfig;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.oauth2.CredentialAuthorizationResponse;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.oauth2.CredentialAuthorizationRequest;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.oauth2.OAuth2AuthorizeRequest;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Date;

@Service
public class OAuth2Service {
	private final QTSPClient qtspClient;
	private final OAuthClientConfig oAuthClientConfig;

	public OAuth2Service(@Autowired QTSPClient qtspClient,
						 @Autowired OAuthClientConfig oAuthClientConfig) {
		this.qtspClient = qtspClient;
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

	private static String getBasicAuthenticationHeader(String username, String password) {
		String valueToEncode = username + ":" + password;
		return "Basic " + Base64.getEncoder().encodeToString(valueToEncode.getBytes());
	}

	public CredentialAuthorizationResponse getOAuth2Authorize(CredentialAuthorizationRequest credentialAuthorization,
															  String hash, Date date, String authorizationBearerHeader) throws Exception{

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

		CredentialAuthorizationResponse responseTemporary = this.qtspClient.requestOAuth2Authorize(credentialAuthorization.getAuthorizationServerUrl(), authorizeRequest, authorizationBearerHeader);
		responseTemporary.setSignature_date(date.getTime());
		return responseTemporary;
	}

	public JSONObject getOAuth2Token(String code) throws Exception{
		String authorizationHeader = getBasicAuthenticationHeader(this.oAuthClientConfig.getClientId(),
			  this.oAuthClientConfig.getClientSecret());
		return this.qtspClient.requestOAuth2Token(this.oAuthClientConfig.getDefaultAuthorizationServerUrl(),
			  code, this.oAuthClientConfig.getClientId(), this.oAuthClientConfig.getRedirectUri(), authorizationHeader);
	}

}
