package eu.europa.ec.eudi.signer.r3.sca.model;

import eu.europa.ec.eudi.signer.r3.sca.DSS_Service;
import eu.europa.ec.eudi.signer.r3.sca.DTO.SignDocRequest.DocumentsSignDocRequest;
import eu.europa.esig.dss.model.DSSDocument;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@Service
public class SignatureService {

    private final DSS_Service dssClient;

    public SignatureService(@Autowired DSS_Service dssClient){
        this.dssClient = dssClient;
    }

    public List<String> calculateHashValue(List<DocumentsSignDocRequest> documents, X509Certificate signingCertificate, List<X509Certificate> certificateChain, String hashAlgorithmOID){
        List<String> doc = new ArrayList<>();
        for (DocumentsSignDocRequest document : documents) {
            DSSDocument dssDocument = dssClient.loadDssDocument(document.getDocument());
            byte[] dataToBeSigned = null;
            if (document.getSignature_format().equals("P")) {
                dataToBeSigned = dssClient.padesToBeSignedData(dssDocument, document.getConformance_level(), document.getSigned_envelope_property(), signingCertificate, certificateChain);
            }

            String dtbs = Base64.getEncoder().encodeToString(dataToBeSigned);
            doc.add(dtbs);
        }
        return doc;
    }

}
