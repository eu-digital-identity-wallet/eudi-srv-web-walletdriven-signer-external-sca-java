package eu.europa.ec.eudi.signer.r3.sca.DTO.SignDocRequest;

import java.util.List;
import jakarta.validation.constraints.NotBlank;

public class DocumentDigestsSignDocRequest {
    private List<String> hashes;
    private String hashAlgorithmOID;
    private String signature_format;
    private String conformance_level;
    @NotBlank
    private String signAlgo;
    private String signAlgoParams;
    private List<AttributeSignDocRequest> signed_props;
    private String signed_envelop_property;

    public List<String> getHashes() {
        return hashes;
    }

    public void setHashes(List<String> hashes) {
        this.hashes = hashes;
    }

    public String getHashAlgorithmOID() {
        return hashAlgorithmOID;
    }

    public void setHashAlgorithmOID(String hashAlgorithmOID) {
        this.hashAlgorithmOID = hashAlgorithmOID;
    }

    public String getSignature_format() {
        return signature_format;
    }

    public void setSignature_format(String signature_format) {
        this.signature_format = signature_format;
    }

    public String getConformance_level() {
        return conformance_level;
    }

    public void setConformance_level(String conformance_level) {
        this.conformance_level = conformance_level;
    }

    public String getSignAlgo() {
        return signAlgo;
    }

    public void setSignAlgo(String signAlgo) {
        this.signAlgo = signAlgo;
    }

    public String getSignAlgoParams() {
        return signAlgoParams;
    }

    public void setSignAlgoParams(String signAlgoParams) {
        this.signAlgoParams = signAlgoParams;
    }

    public List<AttributeSignDocRequest> getSigned_props() {
        return signed_props;
    }

    public void setSigned_props(List<AttributeSignDocRequest> signed_props) {
        this.signed_props = signed_props;
    }

    public String getSigned_envelop_property() {
        return signed_envelop_property;
    }

    public void setSigned_envelop_property(String signed_envelop_property) {
        this.signed_envelop_property = signed_envelop_property;
    }
}
