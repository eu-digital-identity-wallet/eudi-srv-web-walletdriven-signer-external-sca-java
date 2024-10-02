package eu.europa.ec.eudi.signer.r3.sca.model;

import eu.europa.esig.dss.AbstractSignatureParameters;
import eu.europa.esig.dss.alert.ExceptionOnStatusAlert;
import eu.europa.esig.dss.alert.LogOnStatusAlert;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESTimestampParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.cades.signature.CAdESTimestampParameters;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SigDMechanism;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.TimestampParameters;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.jades.signature.JAdESService;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.service.SecureRandomNonceSource;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.OCSPDataLoader;
import eu.europa.esig.dss.service.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.signature.MultipleDocumentsSignatureService;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.OCSPFirstRevocationDataLoadingStrategyFactory;
import eu.europa.esig.dss.validation.RevocationDataVerifier;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;

@Service
public class DSSService {
    private static final Logger fileLogger = LoggerFactory.getLogger("FileLogger");

    public static SignatureLevel checkConformance_level(String conformance_level, String string) {
        String enumValue = mapToEnumValue(conformance_level, string);
        if (enumValue == null) {
            return null;
        }

        try {
            return SignatureLevel.valueByName(enumValue);
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
        }

        return null;
    }

    private static String mapToEnumValue(String conformance_level, String string) {
        String prefix;
        switch (string) {
            case "P":
                prefix = "PAdES_BASELINE_";
                break;
            case "C":
                prefix = "CAdES_BASELINE_";
                break;
            case "J":
                prefix = "JAdES_BASELINE_";
                break;
            case "X":
                prefix = "XAdES_BASELINE_";
                break;
            default:
                fileLogger.error("Session_id:"+ RequestContextHolder.currentRequestAttributes().getSessionId() +","+"Conformance Level invalid.");
                return null;
        }

        switch (conformance_level) {
            case "Ades-B-B":
                return prefix + "B";
            case "Ades-B-LT":
                return prefix + "LT";
            case "Ades-B-LTA":
                return prefix + "LTA";
            case "Ades-B-T":
                return prefix + "T";
            default:
                fileLogger.error("Session_id:"+ RequestContextHolder.currentRequestAttributes().getSessionId() +","+"Conformance Level invalid.");
                return null;
        }
    }

    public static SignatureForm checkSignForm(String signForm) {
        switch (signForm) {
            case "P":
                return SignatureForm.PAdES;
            case "C":
                return SignatureForm.CAdES;
            case "J":
                return SignatureForm.JAdES;
            case "X":
                return SignatureForm.XAdES;
            default:
                fileLogger.error("Session_id:"+ RequestContextHolder.currentRequestAttributes().getSessionId() +","+"Signature Format invalid.");
                return null;
        }
    }

    private static SignatureAlgorithm checkSignAlg(String alg) {
        switch (alg) {
            case "1.2.840.113549.1.1.11":
                return SignatureAlgorithm.RSA_SHA256;
            case "1.2.840.113549.1.1.12":
                return SignatureAlgorithm.RSA_SHA384;
            case "1.2.840.113549.1.1.13":
                return SignatureAlgorithm.RSA_SHA512;
            default:
                return null;
        }
    }

    public static DigestAlgorithm checkSignAlgDigest(String alg) {
        switch (alg) {
            case "1.2.840.113549.1.1.11":
                return DigestAlgorithm.SHA256;
            case "2.16.840.1.101.3.4.2.1":
                return DigestAlgorithm.SHA256;
            case "1.2.840.113549.1.1.12":
                return DigestAlgorithm.SHA384;
            case "2.16.840.1.101.3.4.2.2":
                return DigestAlgorithm.SHA384;
            case "1.2.840.113549.1.1.13":
                return DigestAlgorithm.SHA512;
            case "2.16.840.1.101.3.4.2.3":
                return DigestAlgorithm.SHA512;
            default:
                fileLogger.error("Session_id:"+ RequestContextHolder.currentRequestAttributes().getSessionId() +","+"Signature Digest Algorithm invalid.");
                return null;
        }
    }

    public static ASiCContainerType checkASiCContainerType(String alg) {
        switch (alg) {
            case "No":
                return null;
            case "ASiC-E":
                return ASiCContainerType.ASiC_E;
            case "ASiC-S":
                return ASiCContainerType.ASiC_S;
            default:
                fileLogger.error("Session_id:"+ RequestContextHolder.currentRequestAttributes().getSessionId() +","+"ASICC Container Type invalid.");
                return null;
        }
    }

    public static SignaturePackaging checkEnvProps(String env) {
        switch (env) {
            case "ENVELOPED":
                return SignaturePackaging.ENVELOPED;
            case "ENVELOPING":
                return SignaturePackaging.ENVELOPING;
            case "DETACHED":
                return SignaturePackaging.DETACHED;
            case "INTERNALLY_DETACHED":
                return SignaturePackaging.INTERNALLY_DETACHED;
            default:
                fileLogger.error("Session_id:"+ RequestContextHolder.currentRequestAttributes().getSessionId() +","+"Signature Packaging invalid.");
                return null;
        }
    }

    public DSSDocument loadDssDocument(String document) {
        byte[] dataDocument = Base64.getDecoder().decode(document);
        return new InMemoryDocument(dataDocument);
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    public byte[] DataToBeSignedData(SignatureDocumentForm form) throws CertificateException {

        DocumentSignatureService service = getSignatureService(form.getContainerType(), form.getSignatureForm(),
              form.getTrustedCertificates());

        fileLogger.info("Session_id:"+ RequestContextHolder.currentRequestAttributes().getSessionId() +","+"DataToBeSignedData Service created.");
        AbstractSignatureParameters parameters = fillParameters(form);

        fileLogger.info("Session_id:"+ RequestContextHolder.currentRequestAttributes().getSessionId() +","+"DataToBeSignedData Parameters Filled.");

        DSSDocument toSignDocument = form.getDocumentToSign();
        ToBeSigned toBeSigned = service.getDataToSign(toSignDocument, parameters);
        return toBeSigned.getBytes();

    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    public DSSDocument signDocument(SignatureDocumentForm form) {

        DocumentSignatureService service = getSignatureService(form.getContainerType(), form.getSignatureForm(), form.getTrustedCertificates());

        fileLogger.info("Session_id:"+ RequestContextHolder.currentRequestAttributes().getSessionId() +", signDocument Service created.");

        AbstractSignatureParameters parameters = fillParameters(form);
        fileLogger.info("Session_id:"+ RequestContextHolder.currentRequestAttributes().getSessionId() +", DataToBeSignedData Parameters Filled.");

        System.out.println("######: "+parameters.getCertificateChain().size());

        DSSDocument toSignDocument = form.getDocumentToSign();

        SignatureValue signatureValue = new SignatureValue();
        signatureValue.setAlgorithm(SignatureAlgorithm.getAlgorithm(form.getEncryptionAlgorithm(), form.getDigestAlgorithm()));
        signatureValue.setValue(form.getSignatureValue());

        return service.signDocument(toSignDocument, parameters, signatureValue);
    }

    @SuppressWarnings({ "rawtypes" })
    private AbstractSignatureParameters fillParameters(SignatureDocumentForm form) {

        AbstractSignatureParameters parameters = getSignatureParameters(form.getContainerType(),  form.getSignatureForm());
        parameters.setSignaturePackaging(form.getSignaturePackaging());

        fillParameters(parameters, form);

        return parameters;
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    private void fillParameters(AbstractSignatureParameters parameters, SignatureDocumentForm form) {

        parameters.setSignatureLevel(form.getSignatureLevel());
        parameters.setDigestAlgorithm(form.getDigestAlgorithm());
        parameters.bLevel().setSigningDate(form.getDate());

        CertificateToken signingCertificate = new CertificateToken(form.getCertificate());
        parameters.setSigningCertificate(signingCertificate);

        List<X509Certificate> certificateChainBytes = form.getCertChain();
        List<CertificateToken> certChainToken = new ArrayList<>();
        for (X509Certificate cert : certificateChainBytes) {
            certChainToken.add(new CertificateToken(cert));
        }
        parameters.setCertificateChain(certChainToken);

        fillTimestampParameters(parameters, form);
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    private void fillTimestampParameters(AbstractSignatureParameters parameters, SignatureDocumentForm form) {
        SignatureForm signatureForm = form.getSignatureForm();

        ASiCContainerType containerType = null;
        containerType = form.getContainerType();

        TimestampParameters timestampParameters = getTimestampParameters(containerType, signatureForm);
        timestampParameters.setDigestAlgorithm(form.getDigestAlgorithm());

        parameters.setContentTimestampParameters(timestampParameters);
        parameters.setSignatureTimestampParameters(timestampParameters);
        parameters.setArchiveTimestampParameters(timestampParameters);
    }

    @SuppressWarnings("rawtypes")
    private DocumentSignatureService getSignatureService(ASiCContainerType containerType, SignatureForm signatureForm, CommonTrustedCertificateSource TrustedCertificates) {

        CertificateVerifier cv = new CommonCertificateVerifier();

        cv.setTrustedCertSources(TrustedCertificates);
        cv.setCheckRevocationForUntrustedChains(false);

        OnlineCRLSource onlineCRLSource = new OnlineCRLSource();
        onlineCRLSource.setDataLoader(new CommonsDataLoader());
        cv.setCrlSource(onlineCRLSource);

        OnlineOCSPSource onlineOCSPSource = new OnlineOCSPSource();
        onlineOCSPSource.setDataLoader(new OCSPDataLoader());
        onlineOCSPSource.setNonceSource(new SecureRandomNonceSource());
        cv.setOcspSource(null);

        // Capability to download resources from AIA
        cv.setAIASource(null);

        // cv.setDefaultDigestAlgorithm(DigestAlgorithm.SHA256);

        cv.setAlertOnMissingRevocationData(new ExceptionOnStatusAlert());

        cv.setAlertOnUncoveredPOE(new LogOnStatusAlert(Level.WARN));

        cv.setAlertOnRevokedCertificate(new ExceptionOnStatusAlert());

        cv.setAlertOnInvalidTimestamp(new ExceptionOnStatusAlert());

        cv.setAlertOnNoRevocationAfterBestSignatureTime(new LogOnStatusAlert(Level.ERROR));

        cv.setAlertOnExpiredSignature(new ExceptionOnStatusAlert());

        cv.setRevocationDataLoadingStrategyFactory(new OCSPFirstRevocationDataLoadingStrategyFactory());

        RevocationDataVerifier revocationDataVerifier = RevocationDataVerifier.createDefaultRevocationDataVerifier();
        cv.setRevocationDataVerifier(revocationDataVerifier);

        cv.setRevocationFallback(true);

        DocumentSignatureService service = null;
        if (containerType != null) {
            service = (DocumentSignatureService) getASiCSignatureService(signatureForm, cv);
        } else {
            switch (signatureForm) {
                case CAdES:
                    service = new CAdESService(cv);
                    break;
                case PAdES:
                    service = new PAdESService(cv);
                    break;
                case XAdES:
                    service = new XAdESService(cv);
                    break;
                case JAdES:
                    service = new JAdESService(cv);
                    break;
                default:
                    throw new IllegalArgumentException(String.format("Unknown signature form : %s", signatureForm));
            }
        }

        String tspServer = "http://ts.cartaodecidadao.pt/tsa/server";
        OnlineTSPSource onlineTSPSource = new OnlineTSPSource(tspServer);
        onlineTSPSource.setDataLoader(new TimestampDataLoader());
        service.setTspSource(onlineTSPSource);
        return service;
    }

    @SuppressWarnings("rawtypes")
    private MultipleDocumentsSignatureService getASiCSignatureService(SignatureForm signatureForm, CertificateVerifier cv) {
        MultipleDocumentsSignatureService service = null;
        switch (signatureForm) {
            case CAdES:
                service = new ASiCWithCAdESService(cv);
                break;
            case XAdES:
                service = new ASiCWithXAdESService(cv);
                break;
            default:
                throw new IllegalArgumentException(
                      String.format("Not supported signature form for an ASiC container : %s", signatureForm));
        }
        return service;
    }

    private TimestampParameters getTimestampParameters(ASiCContainerType containerType, SignatureForm signatureForm) {
        TimestampParameters parameters = null;
        if (containerType == null) {
            switch (signatureForm) {
                case CAdES:
                    parameters = new CAdESTimestampParameters();
                    break;
                case XAdES:
                    parameters = new XAdESTimestampParameters();
                    break;
                case PAdES:
                    parameters = new PAdESTimestampParameters();
                    break;
                case JAdES:
                    parameters = new JAdESTimestampParameters();
                    break;
                default:
                    throw new IllegalArgumentException(
                          String.format("Not supported signature form for a time-stamp : %s", signatureForm));
            }

        } else {
            switch (signatureForm) {
                case CAdES:
                    ASiCWithCAdESTimestampParameters asicParameters = new ASiCWithCAdESTimestampParameters();
                    asicParameters.aSiC().setContainerType(containerType);
                    parameters = asicParameters;
                    break;
                case XAdES:
                    parameters = new XAdESTimestampParameters();
                    break;
                default:
                    throw new IllegalArgumentException(
                          String.format("Not supported signature form for an ASiC time-stamp : %s", signatureForm));
            }
        }
        return parameters;
    }

    @SuppressWarnings({ "rawtypes" })
    private AbstractSignatureParameters getSignatureParameters(ASiCContainerType containerType, SignatureForm signatureForm) {
        AbstractSignatureParameters parameters = null;
        if (containerType != null) {
            parameters = getASiCSignatureParameters(containerType, signatureForm);
        } else {
            switch (signatureForm) {
                case CAdES:
                    parameters = new CAdESSignatureParameters();
                    break;
                case PAdES:
                    PAdESSignatureParameters padesParams = new PAdESSignatureParameters();
                    padesParams.setContentSize(9472 * 2); // double reserved space for signature
                    parameters = padesParams;
                    break;
                case XAdES:
                    parameters = new XAdESSignatureParameters();
                    break;
                case JAdES:
                    JAdESSignatureParameters jadesParameters = new JAdESSignatureParameters();
                    jadesParameters.setJwsSerializationType(JWSSerializationType.JSON_SERIALIZATION); // to allow T+
                    // levels +
                    // parallel
                    // signing
                    jadesParameters.setSigDMechanism(SigDMechanism.OBJECT_ID_BY_URI_HASH); // to use by default
                    parameters = jadesParameters;
                    break;
                default:
                    throw new IllegalArgumentException(String.format("Unknown signature form : %s", signatureForm));
            }
        }
        return parameters;
    }

    @SuppressWarnings({ "rawtypes" })
    private AbstractSignatureParameters getASiCSignatureParameters(ASiCContainerType containerType, SignatureForm signatureForm) {
        AbstractSignatureParameters parameters = null;
        switch (signatureForm) {
            case CAdES:
                ASiCWithCAdESSignatureParameters asicCadesParams = new ASiCWithCAdESSignatureParameters();
                asicCadesParams.aSiC().setContainerType(containerType);
                parameters = asicCadesParams;
                break;
            case XAdES:
                ASiCWithXAdESSignatureParameters asicXadesParams = new ASiCWithXAdESSignatureParameters();
                asicXadesParams.aSiC().setContainerType(containerType);
                parameters = asicXadesParams;
                break;
            default:
                throw new IllegalArgumentException(
                      String.format("Not supported signature form for an ASiC container : %s", signatureForm));
        }
        return parameters;
    }
}
