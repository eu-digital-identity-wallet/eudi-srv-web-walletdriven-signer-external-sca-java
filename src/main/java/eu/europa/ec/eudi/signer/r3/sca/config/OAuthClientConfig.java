package eu.europa.ec.eudi.signer.r3.sca.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import java.util.Set;

@ConfigurationProperties(prefix = "oauth-client")
public class OAuthClientConfig {
    private String clientId;
    private String clientSecret;
    private Set<String> clientAuthenticationMethods;
    private String redirectUri;
    private String scope;
    private String defaultAuthorizationServerUrl;

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public Set<String> getClientAuthenticationMethods() {
        return clientAuthenticationMethods;
    }

    public void setClientAuthenticationMethods(Set<String> clientAuthenticationMethods) {
        this.clientAuthenticationMethods = clientAuthenticationMethods;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public String getDefaultAuthorizationServerUrl() {
        return defaultAuthorizationServerUrl;
    }

    public void setDefaultAuthorizationServerUrl(String defaultAuthorizationServerUrl) {
        this.defaultAuthorizationServerUrl = defaultAuthorizationServerUrl;
    }
}
