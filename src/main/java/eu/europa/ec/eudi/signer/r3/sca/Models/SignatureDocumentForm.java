package eu.europa.ec.eudi.signer.r3.sca.Models;

import java.security.cert.X509Certificate;

import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;

import java.util.Date;
import java.util.List;

public class SignatureDocumentForm {
    private DSSDocument documentToSign;
    private SignaturePackaging signaturePackaging;
    private ASiCContainerType containerType;
    private SignatureLevel signatureLevel;
    private DigestAlgorithm digestAlgorithm;
    private X509Certificate certificate;
    private Date date;
    private CommonTrustedCertificateSource trustedCertificates;
    private SignatureForm signatureForm;
    private List<X509Certificate> certChain;
    private EncryptionAlgorithm encryptionAlgorithm;
    private byte[] signatureValue;

    public SignatureDocumentForm() {
    }

    public DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    public void setDocumentToSign(DSSDocument documentToSign) {
        this.documentToSign = documentToSign;
    }

    public SignaturePackaging getSignaturePackaging() {
        return signaturePackaging;
    }

    public void setSignaturePackaging(SignaturePackaging signaturePackaging) {
        this.signaturePackaging = signaturePackaging;
    }

    public ASiCContainerType getContainerType() {
        return containerType;
    }

    public void setContainerType(ASiCContainerType containerType) {
        this.containerType = containerType;
    }

    public SignatureLevel getSignatureLevel() {
        return signatureLevel;
    }

    public void setSignatureLevel(SignatureLevel signatureLevel) {
        this.signatureLevel = signatureLevel;
    }

    public DigestAlgorithm getDigestAlgorithm() {
        return digestAlgorithm;
    }

    public void setDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public void setCertificate(X509Certificate certificate) {
        this.certificate = certificate;
    }

    public Date getDate() {
        return date;
    }

    public void setDate(Date date) {
        this.date = date;
    }

    public CommonTrustedCertificateSource getTrustedCertificates() {
        return trustedCertificates;
    }

    public void setTrustedCertificates(CommonTrustedCertificateSource trustedCertificates) {
        this.trustedCertificates=trustedCertificates;
    }

    public SignatureForm getSignatureForm() {
        return signatureForm;
    }

    public void setSignatureForm(SignatureForm signatureForm) {
        this.signatureForm=signatureForm;
    }

    public List<X509Certificate> getCertChain() {
        return certChain;
    }

    public void setCertChain(List<X509Certificate> certChain) {
        this.certChain = certChain;
    }

    public EncryptionAlgorithm getEncryptionAlgorithm() {
        return encryptionAlgorithm;
    }

    public void setEncryptionAlgorithm(EncryptionAlgorithm encryptionAlgorithm) {
        this.encryptionAlgorithm = encryptionAlgorithm;
    }

    public byte[] getSignatureValue() {
        return signatureValue;
    }

    public void setSignatureValue(byte[] signatureValue) {
        this.signatureValue = signatureValue;
    }

}