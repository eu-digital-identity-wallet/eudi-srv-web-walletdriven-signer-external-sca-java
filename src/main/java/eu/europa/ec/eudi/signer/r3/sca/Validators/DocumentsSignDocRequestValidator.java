package eu.europa.ec.eudi.signer.r3.sca.Validators;

import eu.europa.ec.eudi.signer.r3.sca.DTO.SignDocRequest.DocumentsSignDocRequest;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class DocumentsSignDocRequestValidator
        implements ConstraintValidator<DocumentsSignDocConstraintAnnotation, DocumentsSignDocRequest> {

    @Override
    public void initialize(DocumentsSignDocConstraintAnnotation constraintAnnotation) {

    }

    @Override
    public boolean isValid(DocumentsSignDocRequest request, ConstraintValidatorContext context) {
        if (!request.getSignature_format().equals("C") &&
                !request.getSignature_format().equals("X") &&
                !request.getSignature_format().equals("P") &&
                !request.getSignature_format().equals("J"))
            return false;

        if (request.getDocument() == null) {
            return false;
        }

        if (request.getSignature_format() == null) {
            return false;
        }

        return true;

    }

}
