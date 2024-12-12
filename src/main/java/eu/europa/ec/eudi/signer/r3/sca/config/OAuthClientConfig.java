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

package eu.europa.ec.eudi.signer.r3.sca.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import java.util.Set;

@ConfigurationProperties(prefix = "oauth-client")
public class OAuthClientConfig {
    private String clientId;
    private String clientSecret;
    private String redirectUri;
    private String scope;
    private String defaultAuthorizationServerUrl;
    private String defaultResourceServerUrl;

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

    public String getDefaultResourceServerUrl() {
        return defaultResourceServerUrl;
    }

    public void setDefaultResourceServerUrl(String defaultResourceServerUrl) {
        this.defaultResourceServerUrl = defaultResourceServerUrl;
    }
}
