package eu.europa.ec.eudi.signer.r3.sca.Controllers;

import eu.europa.ec.eudi.signer.r3.sca.DTO.SignaturesSignDocResponse;
import eu.europa.ec.eudi.signer.r3.sca.DTO.SignDocRequest.SignaturesSignDocRequest;
import eu.europa.ec.eudi.signer.r3.sca.model.CredentialsService;
import eu.europa.ec.eudi.signer.r3.sca.model.SignatureService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(value = "/signatures")
public class SignaturesController {

    private final SignatureService signatureService;
    private final CredentialsService credentialsService;

    public SignaturesController(@Autowired CredentialsService credentialsService, @Autowired SignatureService signatureService) throws Exception {
        this.credentialsService = credentialsService;
        this.signatureService = signatureService;
    }

    @PostMapping(value = "/signDoc", consumes = "application/json", produces = "application/json")
    public SignaturesSignDocResponse signDoc(@Valid @RequestBody SignaturesSignDocRequest signDocRequest,
                                             @RequestHeader (name="Authorization") String authorizationBearerHeader) {
        System.out.println(signDocRequest);
        System.out.println("authorization: "+authorizationBearerHeader);

        if (signDocRequest.getCredentialID() == null) {
            System.out.println("To be defined: CredentialID needs to be defined in this implementation.");
            return new SignaturesSignDocResponse();
        }
        CredentialsService.CertificateResponse certificateResponse = this.credentialsService.getCertificateAndCertificateChain(signDocRequest.getRequest_uri(), signDocRequest.getCredentialID(), authorizationBearerHeader);

        if (authorizationBearerHeader == null) {
            System.out.println("To be defined: the current solution expects the credential token to be sent in the SAD.");
            return new SignaturesSignDocResponse();
        }
        if (signDocRequest.getOperationMode().equals("A")) {
            System.out.println("To be defined: the current solution doesn't support assynchronious responses.");
            return new SignaturesSignDocResponse();
        }

        if (signDocRequest.getDocuments() != null) {
            try {
                return this.signatureService.handleDocumentsSignDocRequest(signDocRequest, authorizationBearerHeader, certificateResponse.getCertificate(), certificateResponse.getCertificateChain(), certificateResponse.getSignAlgo()
                );
            } catch (Exception e) {

            }
        }
        return new SignaturesSignDocResponse();
    }
}
