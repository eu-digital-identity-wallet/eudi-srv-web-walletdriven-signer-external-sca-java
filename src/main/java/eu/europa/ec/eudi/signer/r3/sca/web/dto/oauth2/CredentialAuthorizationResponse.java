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

package eu.europa.ec.eudi.signer.r3.sca.web.dto.oauth2;

public class CredentialAuthorizationResponse {
    private String location_wallet;
    private String session_cookie;
    private long signature_date;

    public CredentialAuthorizationResponse(String location, String cookie){
        this.location_wallet = location;
        this.session_cookie = cookie;
    }

    public String getLocation_wallet() {
        return location_wallet;
    }

    public void setLocation_wallet(String location_wallet) {
        this.location_wallet = location_wallet;
    }

    public String getSession_cookie() {
        return session_cookie;
    }

    public void setSession_cookie(String session_cookie) {
        this.session_cookie = session_cookie;
    }

    public long getSignature_date() {
        return signature_date;
    }

    public void setSignature_date(long signature_date) {
        this.signature_date = signature_date;
    }
}
