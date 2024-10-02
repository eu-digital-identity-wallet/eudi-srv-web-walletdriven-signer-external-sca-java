package eu.europa.ec.eudi.signer.r3.sca.web.validator;

import eu.europa.ec.eudi.signer.r3.sca.web.dto.SignDocRequest.SignaturesSignDocRequest;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class SignaturesSignDocRequestValidator
        implements ConstraintValidator<SignDocRequestConstraintAnnotation, SignaturesSignDocRequest> {

    @Override
    public void initialize(SignDocRequestConstraintAnnotation constraintAnnotation) {

    }

    @Override
    public boolean isValid(SignaturesSignDocRequest request, ConstraintValidatorContext context) {
        if (request.getRequest_uri() == null)
            return false;

        return (request.getCredentialID() != null) && (request.getDocuments() != null);
    }

}
