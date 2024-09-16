package eu.europa.ec.eudi.signer.r3.sca.web.validator;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

@Constraint(validatedBy = SignaturesSignDocRequestValidator.class)
@Target({ ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
public @interface SignDocRequestConstraintAnnotation {
    String message() default "The /signDoc body from the HTTP Request is invalid.";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
