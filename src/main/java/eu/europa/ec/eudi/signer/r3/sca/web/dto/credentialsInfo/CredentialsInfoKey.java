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

package eu.europa.ec.eudi.signer.r3.sca.web.dto.credentialsInfo;

import jakarta.validation.constraints.NotBlank;

import java.util.List;

public class CredentialsInfoKey {

    // enabled | disabled
    @NotBlank
    private String status;
    @NotBlank
    private List<String> algo;
    @NotBlank
    private int len;
    private String curve;

    public @NotBlank String getStatus() {
        return status;
    }

    public void setStatus(@NotBlank String status) {
        this.status = status;
    }

    public @NotBlank List<String> getAlgo() {
        return algo;
    }

    public void setAlgo(@NotBlank List<String> algo) {
        this.algo = algo;
    }

    @NotBlank
    public int getLen() {
        return len;
    }

    public void setLen(@NotBlank int len) {
        this.len = len;
    }

    public String getCurve() {
        return curve;
    }

    public void setCurve(String curve) {
        this.curve = curve;
    }

    @Override
    public String toString() {
        return "CredentialsKeyInfoResponse{" +
                "status='" + status + '\'' +
                ", algo=" + algo +
                ", len=" + len +
                ", curve='" + curve + '\'' +
                '}';
    }
}
