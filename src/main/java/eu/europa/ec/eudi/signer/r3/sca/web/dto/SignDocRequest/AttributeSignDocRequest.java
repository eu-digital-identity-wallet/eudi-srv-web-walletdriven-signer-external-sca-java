package eu.europa.ec.eudi.signer.r3.sca.web.dto.SignDocRequest;

import jakarta.validation.constraints.NotBlank;

public class AttributeSignDocRequest {
    @NotBlank
    private String attribute_name;
    private String attribute_value;

    public String getAttribute_name() {
        return attribute_name;
    }

    public void setAttribute_name(String attribute_name) {
        this.attribute_name = attribute_name;
    }

    public String getAttribute_value() {
        return attribute_value;
    }

    public void setAttribute_value(String attribute_value) {
        this.attribute_value = attribute_value;
    }
}
