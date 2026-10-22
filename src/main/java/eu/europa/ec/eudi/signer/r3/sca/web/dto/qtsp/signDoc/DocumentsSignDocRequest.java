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

package eu.europa.ec.eudi.signer.r3.sca.web.dto.qtsp.signDoc;

import java.util.List;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public class DocumentsSignDocRequest {
    @Schema(description = "A base64-encoded document.", required = true)
    @NotBlank(message = "The document must be present in the request")
    private String document;
    @Schema(description = "The name of the document to be signed.")
    private String document_name;
    @Schema(description = "The digital signature format to use when signing the document.", required = true)
    @NotBlank(message = "Signature format cannot be blank")
    @Pattern(regexp = "P|C|X|J", message = "Invalid signature format")
    private String signature_format = null;
    @Schema(description = "The signature conformance level. The default level is AdES-B-B.", required = true)
    @Pattern(regexp = "Ades-B-B|Ades-B-T|Ades-B-LT|Ades-B-LTA|Ades-B|Ades-T|Ades-LT|Ades-LTA",
          message = "Invalid conformance level")
    private String conformance_level = "AdES-B-B";
    @Schema(description = "List of signed attributes.")
    private List<AttributeSignDocRequest> signed_props;
    @Schema(description = "The property concerning the signed envelope.", required = true)
    @Pattern(regexp = "ENVELOPED|ENVELOPING|DETACHED|INTERNALLY_DETACHED",
          message = "Invalid signed envelope property")
    private String signed_envelope_property;
    @Schema(description = "Specifies the signature container type. The default container is 'No'")
    @Pattern(regexp = "No|ASiC-E|ASiC-S", message = "Invalid container value")
    private String container = "No";

    public String getDocument() {
        return document;
    }

    public void setDocument(String document) {
        this.document = document;
    }

    public String getDocument_name() {
        return document_name;
    }

    public void setDocument_name(String document_name) {
        this.document_name = document_name;
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
