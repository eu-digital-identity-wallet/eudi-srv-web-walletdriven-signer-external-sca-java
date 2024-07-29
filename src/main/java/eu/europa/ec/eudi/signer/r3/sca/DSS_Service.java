package eu.europa.ec.eudi.signer.r3.sca;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import org.springframework.stereotype.Service;

import eu.europa.esig.dss.AbstractSignatureParameters;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.cades.signature.CMSSignedDocument;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SigDMechanism;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.signature.JAdESService;
import eu.europa.esig.dss.pades.signature.ExternalCMSService;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
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
    @SuppressWarnings("rawtypes")
    public byte[] cadesToBeSignedData (DSSDocument documentToSign, String string,
        String signed_envelope_property, X509Certificate signingCertificate,
        List<X509Certificate> certificateChain) {

        CertificateVerifier cv = new CommonCertificateVerifier();

        CAdESSignatureParameters signatureParameters = new CAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(new CertificateToken(signingCertificate));
        List<CertificateToken> certChainToken = new ArrayList<>();
        for (X509Certificate cert : certificateChain) {
            certChainToken.add(new CertificateToken(cert));
        }
        signatureParameters.setCertificateChain(certChainToken);
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
        System.out.print("2CAdES\n");

        cv = new CommonCertificateVerifier();
        CAdESService cmsForCAdESGenerationService  = new CAdESService(cv);
        ToBeSigned dataToSign = cmsForCAdESGenerationService.getDataToSign(documentToSign, signatureParameters);
        System.out.print("3CAdES\n");
        return dataToSign.getBytes();

    }
    @SuppressWarnings("rawtypes")
    public byte[] xadesToBeSignedData(DSSDocument documentToSign, String string,
        String signed_envelope_property, X509Certificate signingCertificate,
        List<X509Certificate> certificateChain) {

        CertificateVerifier cv = new CommonCertificateVerifier();

        XAdESSignatureParameters  signatureParameters = new XAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(new CertificateToken(signingCertificate));
        List<CertificateToken> certChainToken = new ArrayList<>();
        for (X509Certificate cert : certificateChain) {
            certChainToken.add(new CertificateToken(cert));
        }
        signatureParameters.setCertificateChain(certChainToken);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
        // signatureParameters.setReason("DSS testing");
        System.out.print("2XAdES\n");

        cv = new CommonCertificateVerifier();
        XAdESService cmsForXAdESGenerationService  = new XAdESService(cv);
        ToBeSigned dataToSign = cmsForXAdESGenerationService.getDataToSign(documentToSign, signatureParameters);
        System.out.print("3XAdES\n");
        return dataToSign.getBytes();

    }

    public byte[] jadesToBeSignedData (DSSDocument documentToSign, String string,
        String signed_envelope_property, X509Certificate signingCertificate,
        List<X509Certificate> certificateChain) {

        CertificateVerifier cv = new CommonCertificateVerifier();

        JAdESSignatureParameters  signatureParameters = new JAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(new CertificateToken(signingCertificate));
        List<CertificateToken> certChainToken = new ArrayList<>();
        for (X509Certificate cert : certificateChain) {
            certChainToken.add(new CertificateToken(cert));
        }
        signatureParameters.setCertificateChain(certChainToken);
        signatureParameters.setJwsSerializationType(JWSSerializationType.JSON_SERIALIZATION);
        signatureParameters.setSigDMechanism(SigDMechanism.OBJECT_ID_BY_URI_HASH);
        signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
        // signatureParameters.setReason("DSS testing");
        System.out.print("2JAdES\n");

        cv = new CommonCertificateVerifier();
        JAdESService cmsForXAdESGenerationService  = new JAdESService(cv);
        ToBeSigned dataToSign = cmsForXAdESGenerationService.getDataToSign(documentToSign, signatureParameters);
        System.out.print("3JAdES\n");
        return dataToSign.getBytes();

    }

    // --------------------

    public byte[] padesToBeSignedData(DSSDocument documentToSign, String conformance_level,
            String signed_envelope_property, X509Certificate signingCertificate,
            List<X509Certificate> certificateChain) {

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

        cv = new CommonCertificateVerifier();
        ExternalCMSService cmsForPAdESGenerationService = new ExternalCMSService(cv);
        ToBeSigned dataToSign = cmsForPAdESGenerationService.getDataToSign(messageDigest, signatureParameters);
        return dataToSign.getBytes();
    }

    public DSSDocument getSignedDocument(DSSDocument documentToSign, byte[] signature,
            X509Certificate signingCertificate,
            List<X509Certificate> certificateChain) {

        SignatureValue signatureValue = new SignatureValue();
        signatureValue.setAlgorithm(SignatureAlgorithm.RSA_SHA256);
        signatureValue.setValue(signature);

        CertificateVerifier cv = new CommonCertificateVerifier();
        CAdESService service = new CAdESService(cv);

        CAdESSignatureParameters signatureParameters = new CAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(new CertificateToken(signingCertificate));
        List<CertificateToken> certChainToken = new ArrayList<>();
        for (X509Certificate cert : certificateChain) {
            certChainToken.add(new CertificateToken(cert));
        }
        signatureParameters.setCertificateChain(certChainToken);
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);

        // Stateless
        service = new CAdESService(cv);
        return service.signDocument(documentToSign, signatureParameters,signatureValue);
    }

    private static class ExternalCMSPAdESService extends PAdESService {
        private static final long serialVersionUID = -2003453716888412577L;
        private byte[] cmsSignedData;

        public ExternalCMSPAdESService(CertificateVerifier certificateVerifier) {
            super(certificateVerifier);
        }

        public DSSMessageDigest getMessageDigest(DSSDocument documentToSign, PAdESSignatureParameters parameters) {
            return super.computeDocumentDigest(documentToSign, parameters);
        }

        @Override
        protected byte[] generateCMSSignedData(final DSSDocument toSignDocument,
                final PAdESSignatureParameters parameters,
                final SignatureValue signatureValue) {
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
