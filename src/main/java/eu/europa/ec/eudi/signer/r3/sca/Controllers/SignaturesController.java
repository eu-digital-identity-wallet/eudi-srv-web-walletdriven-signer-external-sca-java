package eu.europa.ec.eudi.signer.r3.sca.Controllers;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import eu.europa.ec.eudi.signer.r3.sca.DSS_Service;
import eu.europa.ec.eudi.signer.r3.sca.QtspClient;
import eu.europa.ec.eudi.signer.r3.sca.DTO.SignaturesSignDocResponse;
import eu.europa.ec.eudi.signer.r3.sca.DTO.SignaturesSignHashRequest;
import eu.europa.ec.eudi.signer.r3.sca.DTO.SignaturesSignHashResponse;
import eu.europa.ec.eudi.signer.r3.sca.DTO.ValidationInfoSignDocResponse;
import eu.europa.ec.eudi.signer.r3.sca.DTO.SignDocRequest.DocumentsSignDocRequest;
import eu.europa.ec.eudi.signer.r3.sca.DTO.SignDocRequest.SignaturesSignDocRequest;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.model.DSSDocument;
import jakarta.validation.Valid;

import java.io.File;

@RestController
@RequestMapping(value = "/signatures")
public class SignaturesController {

    private final QtspClient qtspClient;
    private final DSS_Service dssClient;
    private final X509Certificate signingCertificate;

    public SignaturesController(@Autowired DSS_Service dssClient, @Autowired QtspClient qtspClient) throws Exception {
        this.dssClient = dssClient;
        this.qtspClient = qtspClient;

        byte[] cert_bytes = Base64.getDecoder().decode(
                "MIIBuzCCASSgAwIBAgIGAY/zF0AhMA0GCSqGSIb3DQEBCwUAMBYxFDASBgNVBAMMC2lzc3Vlcl90ZXN0MB4XDTI0MDYwNzE0MjUzOFoXDTI1MDYwNzE0MjUzOFowFzEVMBMGA1UEAwwMc3ViamVjdF90ZXN0MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCseUUmD8+Okuh5OrLT2LyO6QCNOIidohV7HAjIbgdpSU1C27z+JDWT3cfVbojQ5EzvZM9CDPayHrlnNK8NFD9ggE3rbOn6ATT9iC4qTQvPN3Sdel5OTaVabMuMT2satwbtl8wB98583i4bhJUyHRy7PJnXrOCscyK14GjGnuVwjQIDAQABoxMwETAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4GBACWKec1JiRggmTRm0aQin3SJnsvuF8JS5GlOpea45IGV2gOHws/iFPg8BAaGzQ1d+sG+RHH07xKCll8Xw1QaqLhc+96vNOCvl2cjl7BdLH/fiYurP8Vf0W3lkp5VbRFV2nWwHcOIPBUa8lNK+uV6Z5nPG5Ads12BJD5K8jAHXo2E");

        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        InputStream in = new ByteArrayInputStream(cert_bytes);
        this.signingCertificate = (X509Certificate) certFactory.generateCertificate(in);
        System.out.println(this.signingCertificate.toString());

    }

    @PostMapping(value = "/signDoc", consumes = "application/json", produces = "application/json")
    public SignaturesSignDocResponse signDoc(@Valid @RequestBody SignaturesSignDocRequest signDocRequest,
                                             @RequestHeader (name="Authorization") String authorizationBearerHeader) {

        System.out.println(signDocRequest);
        System.out.println(authorizationBearerHeader);
        String url = signDocRequest.getRequest_uri();
        System.out.println(url);
        if (signDocRequest.getCredentialID() == null) {
            System.out.println("To be defined: CredentialID needs to be defined in this implementation.");
            return new SignaturesSignDocResponse();
        }

        if (signDocRequest.getSAD() == null && authorizationBearerHeader == null) {
            System.out.println(
                    "To be defined: the current solution expects the credential token to be sent in the SAD.");
            return new SignaturesSignDocResponse();
        }

        if (signDocRequest.getOperationMode().equals("A")) {
            System.out.println("To be defined: the current solution doesn't support assynchronious responses.");
            return new SignaturesSignDocResponse();
        }

        if (signDocRequest.getDocuments() != null) {
            try {
                return handleDocumentsSignDocRequest(signDocRequest, url, authorizationBearerHeader);
            } catch (Exception e) {

            }
        }

        if (signDocRequest.getDocumentDigests() != null) {
            try {
                return handleDocumentDigestsSignDocRequest(signDocRequest, url, authorizationBearerHeader);
            } catch (Exception e) {
            }
        }

        return new SignaturesSignDocResponse();
    }

    // i need the signing certificate before hand
    public SignaturesSignDocResponse handleDocumentsSignDocRequest(SignaturesSignDocRequest signDocRequest, String url, String authorizationBearerHeader)
            throws Exception {

        // if signature_format == C => signed_envelope_property = Attached
        // if signature_format == P => signed_envelope_property = Certification
        // if signature_format == X => signed_envelope_property = Enveloped
        // if signature_format == J => signed_envelope_property = Attached

        List<SignaturesSignHashResponse> allResponses = new ArrayList<>();
        for (DocumentsSignDocRequest document : signDocRequest.getDocuments()) {
            DSSDocument dssDocument = dssClient.loadDssDocument(document.getDocument());
            byte[] dataToBeSigned = null;
            /*if (document.getSignature_format().equals("C")) {
                dataToBeSigned = dssClient.cadesToBeSignedData(dssDocument,
                document.getConformance_level(), document.getSigned_envelope_property(),
                this.signingCertificate, new ArrayList<>());
                System.out.println("Not Supported by current version");
            } else*/ if (document.getSignature_format().equals("P")) {
                System.out.print("PAdES\n");
                dataToBeSigned = dssClient.padesToBeSignedData(dssDocument,
                        document.getConformance_level(), document.getSigned_envelope_property(),
                        this.signingCertificate, new ArrayList<>());
                System.out.println("Data To Be Signed Created");
            } else if (document.getSignature_format().equals("X")) {
                System.out.print("XAdES: to be implemented");
                return new SignaturesSignDocResponse();
                // dssClient.xadesToBeSignedData(dssDocument, document.getConformance_level(),
                // document.getSigned_envelope_property());
            } else if (document.getSignature_format().equals("J")) {
                System.out.print("JAdES: to be implemented");
                return new SignaturesSignDocResponse();
                // dssClient.jadesToBeSignedData(dssDocument, document.getConformance_level(),
                // document.getSigned_envelope_property());
            }

            if (dataToBeSigned == null) {
                return new SignaturesSignDocResponse();
            }

            String dtbs = Base64.getEncoder().encodeToString(dataToBeSigned);
            List<String> doc = new ArrayList<>();
            doc.add(dtbs);

            System.out.println(signDocRequest.toString());

            // As the current operation mode only supported is "S", the validity_period and
            // response_uri do not need to be defined
            SignaturesSignHashRequest signHashRequest = new SignaturesSignHashRequest(
                    signDocRequest.getCredentialID(),
                    signDocRequest.getSAD(),
                    doc,
                    null,
                    document.getSignAlgo(),
                    null,
                    signDocRequest.getOperationMode(),
                    -1,
                    null,
                    signDocRequest.getClientData());

            try {
                System.out.println("HTTP Request to QTSP.");
                SignaturesSignHashResponse signHashResponse = qtspClient.requestSignHash(url, signHashRequest, authorizationBearerHeader);
                System.out.println("HTTP Response received.");
                allResponses.add(signHashResponse);
                System.out.println(signHashResponse.toString());
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        List<String> DocumentWithSignature = new ArrayList<>();

        List<String> allSignaturesObjects = new ArrayList<>();
        for (SignaturesSignHashResponse response : allResponses) {

            DocumentsSignDocRequest document = signDocRequest.getDocuments().get(0);
            DSSDocument dssDocument = dssClient.loadDssDocument(document.getDocument());

            if (response.getSignatures() != null) {
                byte[] signature = Base64.getDecoder().decode(response.getSignatures().get(0));
                DSSDocument docSigned = dssClient.getSignedDocument(dssDocument, signature, signingCertificate,
                        new ArrayList<>());

                try {
                    docSigned.setMimeType(MimeType.fromMimeTypeString("application/pdf"));
                    docSigned.save("tests/exampleSigned.pdf");

                    File file = new File("tests/exampleSigned.pdf");
                    byte[] pdfBytes = Files.readAllBytes(file.toPath());

                    DocumentWithSignature.add(Base64.getEncoder().encodeToString(pdfBytes));

                } catch (Exception e) {
                    e.printStackTrace();
                }
            }

            allSignaturesObjects.addAll(response.getSignatures());
        }

        ValidationInfoSignDocResponse validationInfo = null;
        if (signDocRequest.getReturnValidationInfo()) {
            // TODO: obtain the validation info....
            validationInfo = new ValidationInfoSignDocResponse();
        }

        SignaturesSignDocResponse signDocResponse = new SignaturesSignDocResponse(
                DocumentWithSignature,
                allSignaturesObjects,
                null,
                validationInfo);
        
        return signDocResponse;

    }

    public SignaturesSignDocResponse handleDocumentDigestsSignDocRequest(SignaturesSignDocRequest signDocRequest,
            String url, String authorizationBearerHeader)
            throws Exception {

        // for each document digests....
        List<SignaturesSignHashResponse> allResponses = new ArrayList<>();
        for (int i = 0; i < signDocRequest.getDocumentDigests().size(); i++) {
            SignaturesSignHashRequest signHashRequest = new SignaturesSignHashRequest(
                    signDocRequest.getCredentialID(),
                    signDocRequest.getSAD(),
                    signDocRequest.getDocumentDigests().get(i).getHashes(),
                    signDocRequest.getDocumentDigests().get(i).getHashAlgorithmOID(),
                    signDocRequest.getDocumentDigests().get(i).getSignAlgo(),
                    signDocRequest.getDocumentDigests().get(i).getSignAlgoParams(),
                    signDocRequest.getOperationMode(),
                    signDocRequest.getValidity_period(),
                    signDocRequest.getResponse_uri(),
                    signDocRequest.getClientData());

            SignaturesSignHashResponse signHashResponse = qtspClient.requestSignHash(url, signHashRequest, authorizationBearerHeader);
            allResponses.add(signHashResponse);
        }

        List<String> allSignaturesObjects = new ArrayList<>();
        for (int i = 0; i < allResponses.size(); i++) {
            allSignaturesObjects.addAll(allResponses.get(i).getSignatures());
        }

        ValidationInfoSignDocResponse validationInfo = null;
        if (signDocRequest.getReturnValidationInfo()) {
            // TODO: obtain the validation info....
            validationInfo = new ValidationInfoSignDocResponse();
        }

        SignaturesSignDocResponse signDocResponse = new SignaturesSignDocResponse(
                null,
                allSignaturesObjects,
                null,
                validationInfo);

        return signDocResponse;

    }
}
