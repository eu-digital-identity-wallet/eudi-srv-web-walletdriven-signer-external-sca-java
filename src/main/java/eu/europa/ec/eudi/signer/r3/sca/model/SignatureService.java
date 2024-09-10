package eu.europa.ec.eudi.signer.r3.sca.model;

import eu.europa.ec.eudi.signer.r3.sca.DSS_Service;
import eu.europa.ec.eudi.signer.r3.sca.DTO.SignDocRequest.DocumentsSignDocRequest;
import eu.europa.ec.eudi.signer.r3.sca.DTO.SignDocRequest.SignaturesSignDocRequest;
import eu.europa.ec.eudi.signer.r3.sca.DTO.SignaturesSignDocResponse;
import eu.europa.ec.eudi.signer.r3.sca.DTO.SignaturesSignHashRequest;
import eu.europa.ec.eudi.signer.r3.sca.DTO.SignaturesSignHashResponse;
import eu.europa.ec.eudi.signer.r3.sca.DTO.ValidationInfoSignDocResponse;
import eu.europa.ec.eudi.signer.r3.sca.QtspClient;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.model.DSSDocument;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.File;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@Service
public class SignatureService {

    private final QtspClient qtspClient;
    private final DSS_Service dssClient;

    public SignatureService(@Autowired QtspClient qtspClient, @Autowired DSS_Service dssClient){
        this.qtspClient = qtspClient;
        this.dssClient = dssClient;
    }

    public List<String> calculateHashValue(List<DocumentsSignDocRequest> documents, X509Certificate signingCertificate, List<X509Certificate> certificateChain, String hashAlgorithmOID){
        List<String> hashes = new ArrayList<>();
        for (DocumentsSignDocRequest document : documents) {
            System.out.println(document.getDocument());
            DSSDocument dssDocument = dssClient.loadDssDocument(document.getDocument());
            byte[] dataToBeSigned = null;
            switch (document.getSignature_format()) {
                case "C" -> System.out.print("CAdES: to be implemented");
                case "P" ->
                      dataToBeSigned = dssClient.padesToBeSignedData(dssDocument, document.getConformance_level(),
                            document.getSigned_envelope_property(), signingCertificate, certificateChain, hashAlgorithmOID);
                case "X" -> System.out.print("XAdES: to be implemented");
                case "J" -> System.out.print("JAdES: to be implemented");
            }

            if (dataToBeSigned == null)
                continue;

            String dataToBeSignedStringEncoded = Base64.getEncoder().encodeToString(dataToBeSigned);
            String dataToBeSignedURLEncoded = URLEncoder.encode(dataToBeSignedStringEncoded, StandardCharsets.UTF_8);
            hashes.add(dataToBeSignedURLEncoded);
        }
        return hashes;
    }


    // i need the signing certificate before hand
    public SignaturesSignDocResponse handleDocumentsSignDocRequest(SignaturesSignDocRequest signDocRequest, String authorizationBearerHeader, X509Certificate certificate, List<X509Certificate> certificateChain, List<String> signAlgo) throws Exception {
        List<String> hashes = calculateHashValue(signDocRequest.getDocuments(), certificate, certificateChain, signDocRequest.getHashAlgorithmOID());
        for(String s: hashes){
            System.out.println("signDoc: "+ s);
        }

        SignaturesSignHashResponse signHashResponse = null;
        try {
            // As the current operation mode only supported is "S", the validity_period and response_uri do not need to be defined
            SignaturesSignHashRequest signHashRequest = new SignaturesSignHashRequest(signDocRequest.getCredentialID(),
                  null, hashes, signDocRequest.getHashAlgorithmOID(), signAlgo.get(0), null, signDocRequest.getOperationMode(),
                  -1, null, signDocRequest.getClientData());

            signHashResponse = qtspClient.requestSignHash(signDocRequest.getRequest_uri(), signHashRequest, authorizationBearerHeader);
        } catch (Exception e) {
            e.printStackTrace();
        }

        assert signHashResponse != null;
        if(signHashResponse.getSignatures().size() != signDocRequest.getDocuments().size()){
            return new SignaturesSignDocResponse();
        }

        List<String> allSignaturesObjects = new ArrayList<>(signHashResponse.getSignatures());
        List<String> DocumentWithSignature = new ArrayList<>();
        for(int i = 0; i < signDocRequest.getDocuments().size(); i++){
            DocumentsSignDocRequest document = signDocRequest.getDocuments().get(i);
            DSSDocument dssDocument = dssClient.loadDssDocument(document.getDocument());

            byte[] signature = Base64.getDecoder().decode(signHashResponse.getSignatures().get(i));
            DSSDocument docSigned = dssClient.getSignedDocument(dssDocument, signature, certificate, certificateChain, signAlgo.get(0), signDocRequest.getHashAlgorithmOID());

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

        // TODO: obtain the validation info....
        ValidationInfoSignDocResponse validationInfo = null;
        if (signDocRequest.getReturnValidationInfo()) {
            validationInfo = new ValidationInfoSignDocResponse();
        }

        return new SignaturesSignDocResponse(DocumentWithSignature, allSignaturesObjects, null, validationInfo);
    }
}
