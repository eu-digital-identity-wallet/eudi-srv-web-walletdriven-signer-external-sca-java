package eu.europa.ec.eudi.signer.r3.sca.Validators;

import eu.europa.ec.eudi.signer.r3.sca.DTO.SignDocRequest.SignaturesSignDocRequest;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class SignaturesSignDocRequestValidator
        implements ConstraintValidator<SignDocRequestConstraintAnnotation, SignaturesSignDocRequest> {

    @Override
    public void initialize(SignDocRequestConstraintAnnotation constraintAnnotation) {

    }

    @Override
    public boolean isValid(SignaturesSignDocRequest request, ConstraintValidatorContext context) {
        if (!request.getOperationMode().equals("A") && !request.getOperationMode().equals("S"))
            return false;

        if (request.getRequest_uri() == null)
            return false;

        return (request.getCredentialID().equals(null) || request.getSignatureQualifier().equals(null))
                && (request.getDocuments() == null || request.getDocumentDigests() == null);
    }

}
