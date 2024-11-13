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

import eu.europa.ec.eudi.signer.r3.sca.config.OAuthClientConfig;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.oauth2.CredentialAuthorizationResponse;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.oauth2.CredentialAuthorizationRequest;
import eu.europa.ec.eudi.signer.r3.sca.web.dto.oauth2.OAuth2AuthorizeRequest;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Date;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

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
		MessageDigest sha = MessageDigest.getInstance("SHA-256");
		byte[] result = sha.digest(root.getBytes());
		return Base64.getUrlEncoder().withoutPadding().encodeToString(result);
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
