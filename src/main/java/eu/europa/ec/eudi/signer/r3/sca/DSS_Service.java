package eu.europa.ec.eudi.signer.r3.sca;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import org.springframework.stereotype.Service;

import eu.europa.esig.dss.cades.signature.CMSSignedDocument;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.ExternalCMSService;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;

@Service
public class DSS_Service {

    public DSSDocument loadDssDocument(String document) {
        byte[] dataDocument = Base64.getDecoder().decode(document);
        return new InMemoryDocument(dataDocument);
    }

    public void test() {
        System.out.println("This is a test.");
    }

    // importante parameters: conformance_level, signed_envelope_property

    public void xadesToBeSignedData(DSSDocument document, String conformance_level, String signed_envelope_property) {

    }

    public void jadesToBeSignedData(DSSDocument document, String conformance_level, String signed_envelope_property) {

    }

    // --------------------

    public byte[] padesToBeSignedData(DSSDocument documentToSign, String conformance_level,
            String signed_envelope_property, X509Certificate signingCertificate,
            List<X509Certificate> certificateChain, String hashAlgorithmOID) {

        System.out.println(documentToSign.getName());

        Date d = new Date(1725976542769L);
        System.out.println(d.getTime());

        CertificateVerifier cv = new CommonCertificateVerifier();
        ExternalCMSPAdESService service = new ExternalCMSPAdESService(cv);

        PAdESSignatureParameters parameters = new PAdESSignatureParameters();
        parameters.bLevel().setSigningDate(d);
        parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        parameters.setReason("DSS testing");
        parameters.setEncryptionAlgorithm(EncryptionAlgorithm.RSA);
        parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

        DSSMessageDigest messageDigest = service.getMessageDigest(documentToSign, parameters);
        System.out.println(messageDigest.getAlgorithm());
        System.out.println("Message Digest: "+Base64.getEncoder().encodeToString(messageDigest.getValue()));

        PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(d);
        signatureParameters.setSigningCertificate(new CertificateToken(signingCertificate));
        List<CertificateToken> certChainToken = new ArrayList<>();
        for (X509Certificate cert : certificateChain) {
            certChainToken.add(new CertificateToken(cert));
        }
        signatureParameters.setCertificateChain(certChainToken);
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        signatureParameters.setEncryptionAlgorithm(EncryptionAlgorithm.RSA);
        signatureParameters.setReason("DSS testing");

        cv = new CommonCertificateVerifier();
        ExternalCMSService cmsForPAdESGenerationService = new ExternalCMSService(cv);
        ToBeSigned dataToSign = cmsForPAdESGenerationService.getDataToSign(messageDigest, signatureParameters);
        return dataToSign.getBytes();
    }

    public DSSDocument getSignedDocument(DSSDocument documentToSign, byte[] signature,
            X509Certificate signingCertificate, List<X509Certificate> certificateChain, String signAlgo, String hashAlgorithmOID) {

        SignatureValue signatureValue = new SignatureValue();
        signatureValue.setAlgorithm(SignatureAlgorithm.RSA_SHA256);
        signatureValue.setValue(signature);

        CertificateVerifier cv = new CommonCertificateVerifier();
        ExternalCMSPAdESService service = new ExternalCMSPAdESService(cv);
        PAdESSignatureParameters parameters = new PAdESSignatureParameters();
        parameters.bLevel().setSigningDate(new Date());
        parameters.setGenerateTBSWithoutCertificate(true);
        parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        parameters.setReason("DSS testing");
        DSSMessageDigest messageDigest = service.getMessageDigest(documentToSign, parameters);


        PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(new CertificateToken(signingCertificate));
        List<CertificateToken> certChainToken = new ArrayList<>();
        for (X509Certificate cert : certificateChain) {
            certChainToken.add(new CertificateToken(cert));
        }
        signatureParameters.setCertificateChain(certChainToken);
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        signatureParameters.setReason("DSS testing");

        // stateless
        cv = new CommonCertificateVerifier();
        ExternalCMSService cmsForPAdESGenerationService = new ExternalCMSService(cv);
        CMSSignedDocument cmsSignedDocument = cmsForPAdESGenerationService.signMessageDigest(messageDigest, signatureParameters, signatureValue);
        byte[] cmsSignedData = cmsSignedDocument.getBytes();

        // Stateless
        service = new ExternalCMSPAdESService(cv);
        service.setCmsSignedData(cmsSignedData);
        return service.signDocument(documentToSign, signatureParameters, null);
    }

    private static class ExternalCMSPAdESService extends PAdESService {
        private byte[] cmsSignedData;

        public ExternalCMSPAdESService(CertificateVerifier certificateVerifier) {
            super(certificateVerifier);
        }

        public DSSMessageDigest getMessageDigest(DSSDocument documentToSign, PAdESSignatureParameters parameters) {
            return super.computeDocumentDigest(documentToSign, parameters);
        }

        @Override
        protected byte[] generateCMSSignedData(final DSSDocument toSignDocument, final PAdESSignatureParameters parameters, final SignatureValue signatureValue) {
            if (this.cmsSignedData == null) {
                throw new NullPointerException("A CMS signed data must be provided");
            }
            return this.cmsSignedData;
        }

        public void setCmsSignedData(final byte[] cmsSignedData) {
            this.cmsSignedData = cmsSignedData;
        }

    }

    /*
     * public byte[] padesToBeSignedData2(DSSDocument document, String
     * conformance_level, String signed_envelope_property,
     * X509Certificate signingCertificate, List<X509Certificate> certificateChain) {
     * 
     * CertificateVerifier cv = new CommonCertificateVerifier();
     * ExternalCMSService padesCMSGeneratorService = new ExternalCMSService(cv);
     * 
     * PAdESSignatureParameters parameters = new PAdESSignatureParameters();
     * parameters.bLevel().setSigningDate(new Date());
     * parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
     * parameters.setReason("DSS testing");
     * // parameters.setEncryptionAlgorithm(EncryptionAlgorithm.RSA);
     * 
     * PAdESSignatureParameters signatureParameters = new
     * PAdESSignatureParameters();
     * signatureParameters.setSigningCertificate(new
     * CertificateToken(signingCertificate));
     * List<CertificateToken> certChainToken = new ArrayList<>();
     * for (X509Certificate cert : certificateChain) {
     * certChainToken.add(new CertificateToken(cert));
     * }
     * signatureParameters.setCertificateChain(certChainToken);
     * signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
     * signatureParameters.setEncryptionAlgorithm(EncryptionAlgorithm.RSA);
     * 
     * ToBeSigned dataToSign = padesCMSGeneratorService.getDataToSign(messageDigest,
     * signatureParameters);
     * return dataToSign.getBytes();
     * }
     * 
     * // update to return doc sign and not only the CMSSignedData
     * public byte[] createDocumentWithSignature(DSSDocument document, byte[]
     * signature,
     * X509Certificate signingCertificate,
     * List<X509Certificate> certificateChain) {
     * 
     * CertificateVerifier cv = new CommonCertificateVerifier();
     * ExternalCMSService padesCMSGeneratorService = new ExternalCMSService(cv);
     * 
     * SignatureValue signatureValue = new SignatureValue();
     * signatureValue.setAlgorithm(SignatureAlgorithm.RSA_SHA256);
     * signatureValue.setValue(signature);
     * 
     * PAdESSignatureParameters signatureParameters = new
     * PAdESSignatureParameters();
     * signatureParameters.setSigningCertificate(new
     * CertificateToken(signingCertificate));
     * List<CertificateToken> certChainToken = new ArrayList<>();
     * for (X509Certificate cert : certificateChain) {
     * certChainToken.add(new CertificateToken(cert));
     * }
     * signatureParameters.setCertificateChain(certChainToken);
     * signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
     * signatureParameters.setEncryptionAlgorithm(EncryptionAlgorithm.RSA);
     * 
     * // Create a CMS signature using the provided message-digest, signature
     * // parameters and the signature value
     * CMSSignedDocument cmsSignature =
     * padesCMSGeneratorService.signMessageDigest(messageDigest,
     * signatureParameters,
     * signatureValue);
     * CMSSignedData signedData = cmsSignature.getCMSSignedData();
     * signedData.getSignerInfos().getSigners()
     * .forEach(x -> System.out.println(x.getEncryptionAlgOID() + " & " +
     * x.getDigestAlgOID())); // sha256WithRSAEncryption
     * // &
     * System.out.println(signedData.getSignedContentTypeOID()); // data
     * for (AlgorithmIdentifier alg : signedData.getDigestAlgorithmIDs()) { //
     * // sha-256
     * System.out.println(alg.toASN1Primitive().toString());
     * }
     * return cmsSignature.getCMSSignedData().getEncoded();
     * }
     */

    // ------------------

    /*
     * public DSSDocument example1(DSSDocument documentToSign, String
     * conformance_level, String signed_envelope_property,
     * X509Certificate signingCertificate, List<X509Certificate> certificateChain) {
     * PAdESWithExternalCMSService service = new PAdESWithExternalCMSService();
     * 
     * PAdESSignatureParameters parameters = new PAdESSignatureParameters();
     * parameters.bLevel().setSigningDate(new Date());
     * parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
     * parameters.setReason("DSS testing");
     * 
     * DSSMessageDigest messageDigest = service.getMessageDigest(documentToSign,
     * parameters);
     * 
     * // --------------------------
     * 
     * PAdESSignatureParameters signatureParameters = new
     * PAdESSignatureParameters();
     * signatureParameters.bLevel().setSigningDate(new Date());
     * signatureParameters.setSigningCertificate(getSigningCert());
     * signatureParameters.setCertificateChain(getCertificateChain());
     * signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
     * signatureParameters.setReason("DSS testing");
     * 
     * PAdESSignerInfoGeneratorBuilder padesCMSSignedDataBuilder = new
     * PAdESSignerInfoGeneratorBuilder(messageDigest);
     * SignatureAlgorithm signatureAlgorithm =
     * signatureParameters.getSignatureAlgorithm();
     * 
     * CustomContentSigner customContentSigner = new
     * CustomContentSigner(signatureAlgorithm.getJCEId());
     * SignerInfoGenerator signerInfoGenerator =
     * padesCMSSignedDataBuilder.build(signatureParameters,
     * customContentSigner);
     * 
     * CMSSignedDataBuilder cmsSignedDataBuilder = new CMSSignedDataBuilder()
     * .setSigningCertificate(signatureParameters.getSigningCertificate())
     * .setCertificateChain(signatureParameters.getCertificateChain())
     * .setGenerateWithoutCertificates(signatureParameters.
     * isGenerateTBSWithoutCertificate())
     * .setEncapsulate(false);
     * cmsSignedDataBuilder.createCMSSignedData(signerInfoGenerator, new
     * InMemoryDocument(messageDigest.getValue()));
     * 
     * SignatureValue signatureValue = getToken().sign(
     * new ToBeSigned(customContentSigner.getOutputStream().toByteArray()),
     * signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
     * 
     * // ----------------------------
     * }
     * 
     * public DSSDocument createDocumentExample1(DSSDocument documentToSign) {
     * 
     * CustomContentSigner customContentSigner = new
     * CustomContentSigner(signatureAlgorithm.getJCEId(),
     * signatureValue.getValue());
     * signerInfoGenerator = padesCMSSignedDataBuilder.build(signatureParameters,
     * customContentSigner);
     * 
     * CMSSignedData cmsSignedData =
     * cmsSignedDataBuilder.createCMSSignedData(signerInfoGenerator,
     * new InMemoryDocument(messageDigest.getValue()));
     * byte[] encoded = DSSASN1Utils.getDEREncoded(cmsSignedData);
     * 
     * CMSSignedData cmsSignedData = DSSUtils.toCMSSignedData(encoded);
     * CMSSignedDocument cmsSignedDocument = new CMSSignedDocument(cmsSignedData);
     * 
     * // Stateless
     * PAdESWithExternalCMSService service = new PAdESWithExternalCMSService();
     * return service.signDocument(documentToSign, signatureParameters,
     * cmsSignedDocument);
     * 
     * }
     */
}
