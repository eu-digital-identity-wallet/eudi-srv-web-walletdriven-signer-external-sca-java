package eu.europa.ec.eudi.signer.r3.sca.web.dto.CredentialsInfo.CredentialsInfo;

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
