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

package eu.europa.ec.eudi.signer.r3.sca.web.controller;

import eu.europa.ec.eudi.signer.r3.sca.config.OAuthClientConfig;
import eu.europa.ec.eudi.signer.r3.sca.model.OAuth2Service;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.server.ResponseStatusException;

@Controller
public class CallbackController {
    private static final Logger logger = LoggerFactory.getLogger(CallbackController.class);

    private final OAuth2Service oAuth2Service;
    private final OAuthClientConfig oAuthClientConfig;

    public CallbackController(@Autowired OAuth2Service oAuth2Service, @Autowired OAuthClientConfig oAuthClientConfig) {
        this.oAuth2Service = oAuth2Service;
        this.oAuthClientConfig = oAuthClientConfig;
    }

    @GetMapping(value="/credential/oauth/login/code")
    public String credential_authorization_code(@RequestParam("code") String code, Model model){
        try {
            JSONObject json = this.oAuth2Service.getOAuth2Token(code);
            model.addAttribute("body", json.toString());
			model.addAttribute("url", this.oAuthClientConfig.getAppRedirectUri());
            return "successful_authentication";
        } catch (Exception e){
            logger.error(e.getMessage());
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_response");
        }
    }
}
