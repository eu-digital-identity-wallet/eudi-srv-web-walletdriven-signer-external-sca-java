package eu.europa.ec.eudi.signer.r3.sca.web.dto.signDoc;

import jakarta.validation.constraints.NotBlank;
import java.util.List;

public class DocumentsSignDocRequest {
    @NotBlank
    private String document;
    @NotBlank
    private String signature_format = null;
    private String conformance_level = "AdES-B-B";
    private List<AttributeSignDocRequest> signed_props;
    private String signed_envelope_property;
    private String container = "No";

    public String getDocument() {
        return document;
    }

    public void setDocument(String document) {
        this.document = document;
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

    public List<AttributeSignDocRequest> getSigned_props() {
        return signed_props;
    }

    public void setSigned_props(List<AttributeSignDocRequest> signed_props) {
        this.signed_props = signed_props;
    }

    public String getSigned_envelope_property() {
        return signed_envelope_property;
    }

    public void setSigned_envelope_property(String signed_envelope_property) {
        this.signed_envelope_property = signed_envelope_property;
    }

    public String getContainer() {
        return container;
    }

    public void setContainer(String container) {
        this.container = container;
    }
}
