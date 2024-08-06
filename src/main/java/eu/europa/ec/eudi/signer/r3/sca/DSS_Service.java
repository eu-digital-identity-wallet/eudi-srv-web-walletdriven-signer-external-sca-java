package eu.europa.ec.eudi.signer.r3.sca;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import org.springframework.stereotype.Service;

import eu.europa.esig.dss.AbstractSignatureParameters;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.cades.signature.CAdESTimestampParameters;
import eu.europa.esig.dss.cades.signature.CMSSignedDocument;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SigDMechanism;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import eu.europa.esig.dss.jades.HTTPHeader;
import eu.europa.esig.dss.jades.HTTPHeaderDigest;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.signature.JAdESService;
import eu.europa.esig.dss.pades.signature.ExternalCMSService;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.service.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;

@Service
public class DSS_Service {

    public static SignatureLevel checkConformance_level(String conformance_level, char type) {
        String enumValue = mapToEnumValue(conformance_level, type);
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

    private static String mapToEnumValue(String conformance_level, char type) {
        String prefix;
        switch (type) {
            case 'p':
                prefix = "PAdES_BASELINE_";
                break;
            case 'c':
                prefix = "CAdES_BASELINE_";
                break;
            case 'j':
                prefix = "JAdES_BASELINE_";
                break;
            case 'x':
                prefix = "XAdES_BASELINE_";
                break;
            default:
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

    private static DigestAlgorithm checkSignAlgDigest(String alg) {
        switch (alg) {
            case "1.2.840.113549.1.1.11":
                return DigestAlgorithm.SHA256;
            case "1.2.840.113549.1.1.12":
                return DigestAlgorithm.SHA384;
            case "1.2.840.113549.1.1.13":
                return DigestAlgorithm.SHA512;
            default:
                return null;
        }
    }

    private static SignaturePackaging checkEnvProps(String env) {
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
                return null;
        }
    }

    public DSSDocument loadDssDocument(String document) {
        byte[] dataDocument = Base64.getDecoder().decode(document);
        return new InMemoryDocument(dataDocument);
    }

    public void test() {
        System.out.println("This is a test.");
    }

    // importante parameters: conformance_level, signed_envelope_property
    @SuppressWarnings("rawtypes")
    public byte[] cadesToBeSignedData (DSSDocument documentToSign, String conformance_level,
        String signed_envelope_property, X509Certificate signingCertificate,
        List<X509Certificate> certificateChain, String signAlg) {

        CertificateVerifier cv = new CommonCertificateVerifier();

        CAdESSignatureParameters signatureParameters = new CAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(new CertificateToken(signingCertificate));
        List<CertificateToken> certChainToken = new ArrayList<>();
        for (X509Certificate cert : certificateChain) {
            certChainToken.add(new CertificateToken(cert));
        }
        signatureParameters.setCertificateChain(certChainToken);
        
        SignatureLevel aux_sign_level = checkConformance_level(conformance_level, 'c');
        System.out.println("\n\n" + aux_sign_level + "\n\n");
        DigestAlgorithm aux_digest_alg = checkSignAlgDigest(signAlg);
        System.out.println( "\n\n" + aux_digest_alg + "\n\n\n");
        SignaturePackaging aux_sign_pack = checkEnvProps(signed_envelope_property);
        System.out.println("\n\n" + aux_sign_pack + "\n\n\n");

        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_T);
        signatureParameters.setDigestAlgorithm(aux_digest_alg);
        signatureParameters.setSignaturePackaging(aux_sign_pack);
        
        signatureParameters.setGenerateTBSWithoutCertificate(true);
        
        System.out.print("2CAdES\n");

        cv = new CommonCertificateVerifier();
        CAdESService cmsForCAdESGenerationService  = new CAdESService(cv);
        String tspServer = "http://ts.cartaodecidadao.pt/tsa/server";
        OnlineTSPSource onlineTSPSource = new OnlineTSPSource(tspServer);
        onlineTSPSource.setDataLoader(new TimestampDataLoader()); // uses the specific content-type
        cmsForCAdESGenerationService.setTspSource(onlineTSPSource);

        ToBeSigned dataToSign = cmsForCAdESGenerationService.getDataToSign(documentToSign, signatureParameters);
        System.out.print("3CAdES\n");
        return dataToSign.getBytes();

    }
    @SuppressWarnings("rawtypes")
    public byte[] cadesToBeSignedData_asic_E(DSSDocument documentToSign, String conformance_level,
        String signed_envelope_property, X509Certificate signingCertificate,
        List<X509Certificate> certificateChain, String signAlg) {

        CertificateVerifier cv = new CommonCertificateVerifier();

        ASiCWithCAdESSignatureParameters signatureParameters = new ASiCWithCAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(new CertificateToken(signingCertificate));
        List<CertificateToken> certChainToken = new ArrayList<>();
        for (X509Certificate cert : certificateChain) {
            certChainToken.add(new CertificateToken(cert));
        }
        
        SignatureLevel aux_sign_level = checkConformance_level(conformance_level, 'c');
        System.out.println("\n\n" + aux_sign_level + "\n\n");
        DigestAlgorithm aux_digest_alg = checkSignAlgDigest(signAlg);
        System.out.println( "\n\n" + aux_digest_alg + "\n\n\n");
        SignaturePackaging aux_sign_pack = checkEnvProps(signed_envelope_property);
        System.out.println("\n\n" + aux_sign_pack + "\n\n\n");

        signatureParameters.setSignatureLevel(aux_sign_level);
        signatureParameters.setDigestAlgorithm(aux_digest_alg);
        signatureParameters.setSignaturePackaging(aux_sign_pack);
        signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);
        
        System.out.print("2CAdES\n");

        cv = new CommonCertificateVerifier();
        ASiCWithCAdESService cmsForCAdESGenerationService  = new ASiCWithCAdESService(cv);
        ToBeSigned dataToSign = cmsForCAdESGenerationService.getDataToSign(documentToSign, signatureParameters);
        System.out.print("3CAdES\n");
        return dataToSign.getBytes();

    }
    @SuppressWarnings("rawtypes")
    public byte[] cadesToBeSignedData_asic_S(DSSDocument documentToSign, String conformance_level,
        String signed_envelope_property, X509Certificate signingCertificate,
        List<X509Certificate> certificateChain, String signAlg) {

        CertificateVerifier cv = new CommonCertificateVerifier();

        ASiCWithCAdESSignatureParameters signatureParameters = new ASiCWithCAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(new CertificateToken(signingCertificate));
        List<CertificateToken> certChainToken = new ArrayList<>();
        for (X509Certificate cert : certificateChain) {
            certChainToken.add(new CertificateToken(cert));
        }
        
        SignatureLevel aux_sign_level = checkConformance_level(conformance_level, 'c');
        System.out.println("\n\n" + aux_sign_level + "\n\n");
        DigestAlgorithm aux_digest_alg = checkSignAlgDigest(signAlg);
        System.out.println( "\n\n" + aux_digest_alg + "\n\n\n");
        SignaturePackaging aux_sign_pack = checkEnvProps(signed_envelope_property);
        System.out.println("\n\n" + aux_sign_pack + "\n\n\n");

        signatureParameters.setSignatureLevel(aux_sign_level);
        signatureParameters.setDigestAlgorithm(aux_digest_alg);
        signatureParameters.setSignaturePackaging(aux_sign_pack);
        signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);
        
        System.out.print("2CAdES\n");

        cv = new CommonCertificateVerifier();
        ASiCWithCAdESService cmsForCAdESGenerationService  = new ASiCWithCAdESService(cv);
        ToBeSigned dataToSign = cmsForCAdESGenerationService.getDataToSign(documentToSign, signatureParameters);
        System.out.print("3CAdES\n");
        return dataToSign.getBytes();

    }
    @SuppressWarnings("rawtypes")
    public byte[] xadesToBeSignedData(DSSDocument documentToSign, String conformance_level,
        String signed_envelope_property, X509Certificate signingCertificate,
        List<X509Certificate> certificateChain, String signAlg) {

        CertificateVerifier cv = new CommonCertificateVerifier();

        XAdESSignatureParameters  signatureParameters = new XAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(new CertificateToken(signingCertificate));
        List<CertificateToken> certChainToken = new ArrayList<>();
        for (X509Certificate cert : certificateChain) {
            certChainToken.add(new CertificateToken(cert));
        }
        signatureParameters.setCertificateChain(certChainToken);

        SignatureLevel aux_sign_level = checkConformance_level(conformance_level, 'x');
        System.out.println("\n\n SIGN LEVEL: " + aux_sign_level + "\n\n");
        DigestAlgorithm aux_digest_alg = checkSignAlgDigest(signAlg);
        System.out.println( "\n\n DIGEST ALG: " + aux_digest_alg + "\n\n\n");
        SignaturePackaging aux_sign_pack = checkEnvProps(signed_envelope_property);
        System.out.println("\n\n SIGN PACK: " + aux_sign_pack + "\n\n\n");

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
    @SuppressWarnings("rawtypes")
    public byte[] xadesToBeSignedData_asic_E(DSSDocument documentToSign, String conformance_level,
        String signed_envelope_property, X509Certificate signingCertificate,
        List<X509Certificate> certificateChain, String signAlg) {

        CertificateVerifier cv = new CommonCertificateVerifier();

        ASiCWithXAdESSignatureParameters signatureParameters = new ASiCWithXAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(new CertificateToken(signingCertificate));
        List<CertificateToken> certChainToken = new ArrayList<>();
        for (X509Certificate cert : certificateChain) {
            certChainToken.add(new CertificateToken(cert));
        }
        
        SignatureLevel aux_sign_level = checkConformance_level(conformance_level, 'x');
        System.out.println("\n\n" + aux_sign_level + "\n\n");
        DigestAlgorithm aux_digest_alg = checkSignAlgDigest(signAlg);
        System.out.println( "\n\n" + aux_digest_alg + "\n\n\n");
        SignaturePackaging aux_sign_pack = checkEnvProps(signed_envelope_property);
        System.out.println("\n\n" + aux_sign_pack + "\n\n\n");

        signatureParameters.setSignatureLevel(aux_sign_level);
        signatureParameters.setDigestAlgorithm(aux_digest_alg);
        signatureParameters.setSignaturePackaging(aux_sign_pack);
        signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);
        
        System.out.print("2XAdES\n");

        cv = new CommonCertificateVerifier();
        ASiCWithXAdESService cmsForCAdESGenerationService  = new ASiCWithXAdESService(cv);
        ToBeSigned dataToSign = cmsForCAdESGenerationService.getDataToSign(documentToSign, signatureParameters);
        System.out.print("3XAdES\n");
        return dataToSign.getBytes();

    }
    @SuppressWarnings("rawtypes")
    public byte[] xadesToBeSignedData_asic_S(DSSDocument documentToSign, String conformance_level,
        String signed_envelope_property, X509Certificate signingCertificate,
        List<X509Certificate> certificateChain, String signAlg) {

        CertificateVerifier cv = new CommonCertificateVerifier();

        ASiCWithXAdESSignatureParameters signatureParameters = new ASiCWithXAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(new CertificateToken(signingCertificate));
        List<CertificateToken> certChainToken = new ArrayList<>();
        for (X509Certificate cert : certificateChain) {
            certChainToken.add(new CertificateToken(cert));
        }
        
        SignatureLevel aux_sign_level = checkConformance_level(conformance_level, 'x');
        System.out.println("\n\n" + aux_sign_level + "\n\n");
        DigestAlgorithm aux_digest_alg = checkSignAlgDigest(signAlg);
        System.out.println( "\n\n" + aux_digest_alg + "\n\n\n");
        SignaturePackaging aux_sign_pack = checkEnvProps(signed_envelope_property);
        System.out.println("\n\n" + aux_sign_pack + "\n\n\n");

        signatureParameters.setSignatureLevel(aux_sign_level);
        signatureParameters.setDigestAlgorithm(aux_digest_alg);
        signatureParameters.setSignaturePackaging(aux_sign_pack);
        signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);
        
        System.out.print("2XAdES\n");

        cv = new CommonCertificateVerifier();
        ASiCWithXAdESService cmsForCAdESGenerationService  = new ASiCWithXAdESService(cv);
        ToBeSigned dataToSign = cmsForCAdESGenerationService.getDataToSign(documentToSign, signatureParameters);
        System.out.print("3XAdES\n");
        return dataToSign.getBytes();

    }
    public byte[] jadesToBeSignedData (DSSDocument documentToSign, String conformance_level,
        String signed_envelope_property, X509Certificate signingCertificate,
        List<X509Certificate> certificateChain, String signAlg) {

        CertificateVerifier cv = new CommonCertificateVerifier();

        JAdESSignatureParameters  signatureParameters = new JAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(new CertificateToken(signingCertificate));
        List<CertificateToken> certChainToken = new ArrayList<>();
        for (X509Certificate cert : certificateChain) {
            certChainToken.add(new CertificateToken(cert));
        }
        signatureParameters.setCertificateChain(certChainToken);
        signatureParameters.setJwsSerializationType(JWSSerializationType.COMPACT_SERIALIZATION);

        SignatureLevel aux_sign_level = checkConformance_level(conformance_level, 'j');
        System.out.println("\n\n" + aux_sign_level + "\n\n");
        DigestAlgorithm aux_digest_alg = checkSignAlgDigest(signAlg);
        System.out.println( "\n\n" + aux_digest_alg + "\n\n\n");
        SignaturePackaging aux_sign_pack = checkEnvProps(signed_envelope_property);
        System.out.println("\n\n" + aux_sign_pack + "\n\n\n");

        signatureParameters.setSignatureLevel(aux_sign_level);
        signatureParameters.setDigestAlgorithm(aux_digest_alg);
        signatureParameters.setSignaturePackaging(aux_sign_pack);
        // signatureParameters.setReason("DSS testing");
        System.out.print("2JAdES\n");

        if(signed_envelope_property.equals("DETACHED")) {
            System.out.println("\n\n JADES detached \n\n");
            signatureParameters.setSigDMechanism(SigDMechanism.HTTP_HEADERS);
            signatureParameters.setBase64UrlEncodedPayload(false);
            List<DSSDocument> documentsToSign = new ArrayList<>();
            documentsToSign.add(new HTTPHeader("content-type", "application/json"));
            documentsToSign.add(new HTTPHeaderDigest(documentToSign, DigestAlgorithm.SHA256));
            
            cv = new CommonCertificateVerifier();
            JAdESService cmsForJAdESGenerationService  = new JAdESService(cv);
            ToBeSigned dataToSign = cmsForJAdESGenerationService.getDataToSign(documentsToSign, signatureParameters);
            System.out.print("3JAdES\n");
            return dataToSign.getBytes();
        }
        else {  
            cv = new CommonCertificateVerifier();
            JAdESService cmsForJAdESGenerationService  = new JAdESService(cv);
            ToBeSigned dataToSign = cmsForJAdESGenerationService.getDataToSign(documentToSign, signatureParameters);
            System.out.print("3JAdES\n");
            return dataToSign.getBytes();
        }


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

        SignatureLevel aux_conf_level = checkConformance_level(conformance_level, 'p');

        parameters.setSignatureLevel(aux_conf_level);
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
        signatureParameters.setSignatureLevel(aux_conf_level);
        signatureParameters.setReason("DSS testing");

        cv = new CommonCertificateVerifier();
        ExternalCMSService cmsForPAdESGenerationService = new ExternalCMSService(cv);
        ToBeSigned dataToSign = cmsForPAdESGenerationService.getDataToSign(messageDigest, signatureParameters);
        System.out.println("pades funcao 1 \n\n\n");
        return dataToSign.getBytes();
    }

    public DSSDocument getSignedDocument(DSSDocument documentToSign, byte[] signature,
            X509Certificate signingCertificate,
            List<X509Certificate> certificateChain, String signAlg, String sign_format, String conform_level, String envelope_props,
            String container) {

        SignatureValue signatureValue = new SignatureValue();
        SignatureAlgorithm aux_alg = checkSignAlg(signAlg);
        signatureValue.setAlgorithm(aux_alg);
        signatureValue.setValue(signature);
        System.out.println("\n\n" + aux_alg + "\n\n\n");

        CertificateVerifier cv = new CommonCertificateVerifier();

        if (sign_format.equals("C")) {
            if(container.equals("ASiC-E")) {
                System.out.print("CAdES ASiC-E\n");
                ASiCWithCAdESService service = new ASiCWithCAdESService(cv);
                ASiCWithCAdESSignatureParameters signatureParameters = new ASiCWithCAdESSignatureParameters();

                signatureParameters.bLevel().setSigningDate(new Date());
                signatureParameters.setSigningCertificate(new CertificateToken(signingCertificate));
                List<CertificateToken> certChainToken = new ArrayList<>();
                for (X509Certificate cert : certificateChain) {
                    certChainToken.add(new CertificateToken(cert));
                }
                signatureParameters.setCertificateChain(certChainToken);

                SignatureLevel aux_sign_level = checkConformance_level(conform_level, 'c');
                System.out.println("\n\n" + aux_sign_level + "\n\n");
                DigestAlgorithm aux_digest_alg = checkSignAlgDigest(signAlg);
                System.out.println( "\n\n" + aux_digest_alg + "\n\n\n");
                SignaturePackaging aux_sign_pack = checkEnvProps(envelope_props);
                System.out.println("\n\n" + aux_sign_pack + "\n\n\n");

                signatureParameters.setSignatureLevel(aux_sign_level);
                signatureParameters.setDigestAlgorithm(aux_digest_alg);
                signatureParameters.setSignaturePackaging(aux_sign_pack);
                signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

                service = new ASiCWithCAdESService(cv);
                return service.signDocument(documentToSign, signatureParameters,signatureValue);
            }
            else if (container.equals("ASiC-S")) {
                System.out.print("CAdES ASiC-S\n");
                ASiCWithCAdESService service = new ASiCWithCAdESService(cv);
                ASiCWithCAdESSignatureParameters signatureParameters = new ASiCWithCAdESSignatureParameters();

                signatureParameters.bLevel().setSigningDate(new Date());
                signatureParameters.setSigningCertificate(new CertificateToken(signingCertificate));
                List<CertificateToken> certChainToken = new ArrayList<>();
                for (X509Certificate cert : certificateChain) {
                    certChainToken.add(new CertificateToken(cert));
                }
                signatureParameters.setCertificateChain(certChainToken);

                SignatureLevel aux_sign_level = checkConformance_level(conform_level, 'c');
                System.out.println("\n\n" + aux_sign_level + "\n\n");
                DigestAlgorithm aux_digest_alg = checkSignAlgDigest(signAlg);
                System.out.println( "\n\n" + aux_digest_alg + "\n\n\n");
                SignaturePackaging aux_sign_pack = checkEnvProps(envelope_props);
                System.out.println("\n\n" + aux_sign_pack + "\n\n\n");

                signatureParameters.setSignatureLevel(aux_sign_level);
                signatureParameters.setDigestAlgorithm(aux_digest_alg);
                signatureParameters.setSignaturePackaging(aux_sign_pack);
                signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);

                service = new ASiCWithCAdESService(cv);
                return service.signDocument(documentToSign, signatureParameters,signatureValue);

            }
            else { 
                System.out.print("CAdES\n");
                CAdESService service = new CAdESService(cv);
                CAdESSignatureParameters signatureParameters = new CAdESSignatureParameters();

                signatureParameters.bLevel().setSigningDate(new Date());
                signatureParameters.setSigningCertificate(new CertificateToken(signingCertificate));
                List<CertificateToken> certChainToken = new ArrayList<>();
                for (X509Certificate cert : certificateChain) {
                    certChainToken.add(new CertificateToken(cert));
                }
                signatureParameters.setCertificateChain(certChainToken);

                SignatureLevel aux_sign_level = checkConformance_level(conform_level, 'c');
                System.out.println("\n\n" + aux_sign_level + "\n\n");
                DigestAlgorithm aux_digest_alg = checkSignAlgDigest(signAlg);
                System.out.println( "\n\n" + aux_digest_alg + "\n\n\n");
                SignaturePackaging aux_sign_pack = checkEnvProps(envelope_props);
                System.out.println("\n\n" + aux_sign_pack + "\n\n\n");

                signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_T);
                signatureParameters.setDigestAlgorithm(aux_digest_alg);
                signatureParameters.setSignaturePackaging(aux_sign_pack);
                signatureParameters.setGenerateTBSWithoutCertificate(true);

                service = new CAdESService(cv);
                System.out.println("teste");
                String tspServer = "http://ts.cartaodecidadao.pt/tsa/server";
                OnlineTSPSource onlineTSPSource = new OnlineTSPSource(tspServer);
                onlineTSPSource.setDataLoader(new TimestampDataLoader()); // uses the specific content-type
                service.setTspSource(onlineTSPSource);

                DSSDocument signed_document= service.signDocument(documentToSign, signatureParameters,signatureValue);
                System.out.println("teste2");


                return signed_document;
            }

        } else if (sign_format.equals("P")) {
            System.out.print("PAdES\n");
            PAdESService service = new PAdESService(cv);
            PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();

            signatureParameters.bLevel().setSigningDate(new Date());
            signatureParameters.setSigningCertificate(new CertificateToken(signingCertificate));
            List<CertificateToken> certChainToken = new ArrayList<>();
            for (X509Certificate cert : certificateChain) {
                certChainToken.add(new CertificateToken(cert));
            }
            signatureParameters.setCertificateChain(certChainToken);

            SignatureLevel aux_sign_level = checkConformance_level(conform_level, 'p');
            System.out.println("\n\n" + aux_sign_level + "\n\n");
            DigestAlgorithm aux_digest_alg = checkSignAlgDigest(signAlg);
            System.out.println( "\n\n" + aux_digest_alg + "\n\n\n");
            SignaturePackaging aux_sign_pack = checkEnvProps(envelope_props);
            System.out.println("\n\n" + aux_sign_pack + "\n\n\n");

            signatureParameters.setSignatureLevel(aux_sign_level);
            signatureParameters.setDigestAlgorithm(aux_digest_alg);
            signatureParameters.setSignaturePackaging(aux_sign_pack);
            
            service = new PAdESService(cv);
            return service.signDocument(documentToSign, signatureParameters,signatureValue);

        } else if (sign_format.equals("X")) {
            if(container.equals("ASiC-E")) {
                System.out.print("XAdES ASiC-E\n");
                ASiCWithXAdESService service = new ASiCWithXAdESService(cv);
                ASiCWithXAdESSignatureParameters signatureParameters = new ASiCWithXAdESSignatureParameters();
                
                signatureParameters.bLevel().setSigningDate(new Date());
                signatureParameters.setSigningCertificate(new CertificateToken(signingCertificate));
                List<CertificateToken> certChainToken = new ArrayList<>();
                for (X509Certificate cert : certificateChain) {
                    certChainToken.add(new CertificateToken(cert));
                }
                signatureParameters.setCertificateChain(certChainToken);

                SignatureLevel aux_sign_level = checkConformance_level(conform_level, 'x');
                System.out.println("\n\n" + aux_sign_level + "\n\n");
                DigestAlgorithm aux_digest_alg = checkSignAlgDigest(signAlg);
                System.out.println( "\n\n" + aux_digest_alg + "\n\n\n");
                SignaturePackaging aux_sign_pack = checkEnvProps(envelope_props);
                System.out.println("\n\n" + aux_sign_pack + "\n\n\n");

                signatureParameters.setSignatureLevel(aux_sign_level);
                signatureParameters.setDigestAlgorithm(aux_digest_alg);
                signatureParameters.setSignaturePackaging(aux_sign_pack);
                signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

                service = new ASiCWithXAdESService(cv);
                return service.signDocument(documentToSign, signatureParameters,signatureValue);
            }
            else if (container.equals("ASiC-S")) {
                System.out.print("XAdES ASiC-S\n");
                ASiCWithXAdESService service = new ASiCWithXAdESService(cv);
                ASiCWithXAdESSignatureParameters signatureParameters = new ASiCWithXAdESSignatureParameters();

                signatureParameters.bLevel().setSigningDate(new Date());
                signatureParameters.setSigningCertificate(new CertificateToken(signingCertificate));
                List<CertificateToken> certChainToken = new ArrayList<>();
                for (X509Certificate cert : certificateChain) {
                    certChainToken.add(new CertificateToken(cert));
                }
                signatureParameters.setCertificateChain(certChainToken);

                SignatureLevel aux_sign_level = checkConformance_level(conform_level, 'x');
                System.out.println("\n\n" + aux_sign_level + "\n\n");
                DigestAlgorithm aux_digest_alg = checkSignAlgDigest(signAlg);
                System.out.println( "\n\n" + aux_digest_alg + "\n\n\n");
                SignaturePackaging aux_sign_pack = checkEnvProps(envelope_props);
                System.out.println("\n\n" + aux_sign_pack + "\n\n\n");

                signatureParameters.setSignatureLevel(aux_sign_level);
                signatureParameters.setDigestAlgorithm(aux_digest_alg);
                signatureParameters.setSignaturePackaging(aux_sign_pack);
                signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);

                service = new ASiCWithXAdESService(cv);
                return service.signDocument(documentToSign, signatureParameters,signatureValue);

            }
            else {
                System.out.print("XAdES\n");
                XAdESService service = new XAdESService(cv);
                XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();

                signatureParameters.bLevel().setSigningDate(new Date());
                signatureParameters.setSigningCertificate(new CertificateToken(signingCertificate));
                List<CertificateToken> certChainToken = new ArrayList<>();
                for (X509Certificate cert : certificateChain) {
                    certChainToken.add(new CertificateToken(cert));
                }
                signatureParameters.setCertificateChain(certChainToken);

                SignatureLevel aux_sign_level = checkConformance_level(conform_level, 'x');
                System.out.println("\n\n" + aux_sign_level + "\n\n");
                DigestAlgorithm aux_digest_alg = checkSignAlgDigest(signAlg);
                System.out.println( "\n\n" + aux_digest_alg + "\n\n\n");
                SignaturePackaging aux_sign_pack = checkEnvProps(envelope_props);
                System.out.println("\n\n" + aux_sign_pack + "\n\n\n");

                signatureParameters.setSignatureLevel(aux_sign_level);
                signatureParameters.setDigestAlgorithm(aux_digest_alg);
                signatureParameters.setSignaturePackaging(aux_sign_pack);
                
                service = new XAdESService(cv);
                return service.signDocument(documentToSign, signatureParameters,signatureValue);
            }
            
        } else if (sign_format.equals("J")) {
            System.out.print("JAdES\n");
            JAdESService service = new JAdESService(cv);
            JAdESSignatureParameters signatureParameters = new JAdESSignatureParameters();

            signatureParameters.bLevel().setSigningDate(new Date());
            signatureParameters.setSigningCertificate(new CertificateToken(signingCertificate));
            List<CertificateToken> certChainToken = new ArrayList<>();
            for (X509Certificate cert : certificateChain) {
                certChainToken.add(new CertificateToken(cert));
            }
            signatureParameters.setCertificateChain(certChainToken);

            SignatureLevel aux_sign_level = checkConformance_level(conform_level, 'j');
            System.out.println("\n\n" + aux_sign_level + "\n\n");
            DigestAlgorithm aux_digest_alg = checkSignAlgDigest(signAlg);
            System.out.println( "\n\n" + aux_digest_alg + "\n\n\n");
            SignaturePackaging aux_sign_pack = checkEnvProps(envelope_props);
            System.out.println("\n\n" + aux_sign_pack + "\n\n\n");

            signatureParameters.setSignatureLevel(aux_sign_level);
            signatureParameters.setDigestAlgorithm(aux_digest_alg);
            signatureParameters.setSignaturePackaging(aux_sign_pack);
            signatureParameters.setJwsSerializationType(JWSSerializationType.COMPACT_SERIALIZATION);

            if(envelope_props.equals("DETACHED")) {
                System.out.println("\n\n JADES detached \n\n");
                signatureParameters.setSigDMechanism(SigDMechanism.HTTP_HEADERS);
                signatureParameters.setBase64UrlEncodedPayload(false);
                List<DSSDocument> documentsToSign = new ArrayList<>();
                documentsToSign.add(new HTTPHeader("content-type", "application/json"));
                documentsToSign.add(new HTTPHeaderDigest(documentToSign, DigestAlgorithm.SHA256));
                service = new JAdESService(cv);
                return service.signDocument(documentsToSign, signatureParameters,signatureValue);
            }
            else {
                service = new JAdESService(cv);
                return service.signDocument(documentToSign, signatureParameters,signatureValue);
            }
            

        }

        System.out.println("\n\n null \n\n");

        // Stateless
        return null;
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
