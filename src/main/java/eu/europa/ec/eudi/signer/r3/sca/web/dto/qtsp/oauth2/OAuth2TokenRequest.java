package eu.europa.ec.eudi.signer.r3.sca.web.dto.qtsp.oauth2;

public class OAuth2TokenRequest {
	// authorization_code | client_credentials | refresh_token
	private String grant_type;
	private String code;
	private String refresh_token;
	private String client_id;
	private String client_secret;
	private String client_assertion;
	private String client_assertion_type;
	private String redirect_uri;
	private String authorization_details;
	private String code_verifier;

	public String getGrant_type() {
		return grant_type;
	}

	public void setGrant_type(String grant_type) {
		this.grant_type = grant_type;
	}

	public String getCode() {
		return code;
	}

	public void setCode(String code) {
		this.code = code;
	}

	public String getRefresh_token() {
		return refresh_token;
	}

	public void setRefresh_token(String refresh_token) {
		this.refresh_token = refresh_token;
	}

	public String getClient_id() {
		return client_id;
	}

	public void setClient_id(String client_id) {
		this.client_id = client_id;
	}

	public String getClient_secret() {
		return client_secret;
	}

	public void setClient_secret(String client_secret) {
		this.client_secret = client_secret;
	}

	public String getClient_assertion() {
		return client_assertion;
	}

	public void setClient_assertion(String client_assertion) {
		this.client_assertion = client_assertion;
	}

	public String getClient_assertion_type() {
		return client_assertion_type;
	}

	public void setClient_assertion_type(String client_assertion_type) {
		this.client_assertion_type = client_assertion_type;
	}

	public String getRedirect_uri() {
		return redirect_uri;
	}

	public void setRedirect_uri(String redirect_uri) {
		this.redirect_uri = redirect_uri;
	}

	public String getAuthorization_details() {
		return authorization_details;
	}

	public void setAuthorization_details(String authorization_details) {
		this.authorization_details = authorization_details;
	}

	public String getCode_verifier() {
		return code_verifier;
	}

	public void setCode_verifier(String code_verifier) {
		this.code_verifier = code_verifier;
	}
}
