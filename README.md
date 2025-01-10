# EUDI Wallet-driven external SCA

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

:heavy_exclamation_mark: **Important!** Before you proceed, please read
the [EUDI Wallet Reference Implementation project description](https://github.com/eu-digital-identity-wallet/.github/blob/main/profile/reference-implementation.md)

## Table of contents

- [EUDI Wallet-driven external SCA](#eudi-wallet-driven-external-sca)
  - [Table of contents](#table-of-contents)
  - [Overview](#overview)
  - [Disclaimer](#disclaimer)
  - [Sequence Diagrams](#sequence-diagrams)
    - [Credential Authorization](#credential-authorization)
  - [Endpoints](#endpoints)
    - [Calculate Hash Endpoint](#calculate-hash-endpoint)
    - [Obtain Signed Document Endpoint](#obtain-signed-document-endpoint)
  - [Deployment](#deployment)
    - [Requirements](#requirements)
    - [Signature Creation Application](#signature-creation-application)
  - [How to contribute](#how-to-contribute)
  - [License](#license)
    - [Third-party component licenses](#third-party-component-licenses)
    - [License details](#license-details)


## Overview

This is a REST API server that implements the wallet-driven SCA for the remote Qualified Electronic Signature component of the EUDI Wallet.
The SCA provides endpoints that allow to calculate the hash value of a document and obtain the signed document given the signature value.

Currently, the server is running at "https://walletcentric.signer.eudiw.dev", but you can [deploy](#deployment) it in your environment.


The Wallet Centric rQES Specification can be found [here](docs/rqes-walledriven.md).

This server can be used with the servers from [eudi-srv-web-walletdriven-signer-qtsp-java](https://github.com/eu-digital-identity-wallet/eudi-srv-web-walletdriven-signer-qtsp-java)
to deploy a remote Qualified Electronic Signature (rQES) component, as described in the previous specification.

## Disclaimer

The released software is an initial development release version:

-   The initial development release is an early endeavor reflecting the efforts of a short timeboxed
    period, and by no means can be considered as the final product.
-   The initial development release may be changed substantially over time, might introduce new
    features but also may change or remove existing ones, potentially breaking compatibility with your
    existing code.
-   The initial development release is limited in functional scope.
-   The initial development release may contain errors or design flaws and other problems that could
    cause system or other failures and data loss.
-   The initial development release has reduced security, privacy, availability, and reliability
    standards relative to future releases. This could make the software slower, less reliable, or more
    vulnerable to attacks than mature software.
-   The initial development release is not yet comprehensively documented.
-   Users of the software must perform sufficient engineering and additional testing in order to
    properly evaluate their application and determine whether any of the open-sourced components is
    suitable for use in that application.
-   We strongly recommend not putting this version of the software into production use.
-   Only the latest version of the software will be supported

## Sequence Diagrams

### Credential Authorization

```mermaid
sequenceDiagram
    title Document Signing

    actor U as UserAgent
    participant EW as EUDI Wallet
    participant SCA as Signature Creation Application
    participant AS as Authorization Server (QTSP)
    participant RS as Resource Server (QTSP)
    participant OIDV as OID4VP Verifier

    U->>+EW: Chooses credential to use
    U->>+EW: Request document signing
    EW->>+RS: /csc/v2/credentials/info
    RS->>-EW: credentials info

    EW->>+SCA: "calculate hash" (certificates, document to sign)
    SCA->>-EW: hash value

    EW->>+AS: /oauth2/authorize?...&redirect_uri=wallet://login/oauth2/code&...
    AS->>+OIDV: Authorization Request (Post dev.verifier-backend.eudiw.dev/ui/presentations?redirect_uri={oid4vp_redirect_uri})
    OIDV->>-AS: Authorization Request returns
    AS->>+AS: Generate link to Wallet
    AS->>-EW: Redirect to link in the Wallet
    EW->>-U: Request Authorization

    U->>+EW: Authorize (Shares PID)
    EW->>+AS: Redirect to oid4vp_redirect_uri
    AS->>+OIDV: Request VP Token
    OIDV->>-AS: Get and validate VP Token
    AS->>-EW: Returns session token (successful authentication) & Redirects to /oauth2/authorize
    EW->>+AS: GET /oauth2/authorize?...&redirect_uri=wallet://oauth2/callback&... [Cookie JSession]
    AS->>-EW: Redirect to wallet://login/oauth2/code?code={code}
    EW->>+EW: Get wallet://login/oauth2/code....
    EW->>+AS: /oauth2/token?code={code}
    AS->>-EW: access token authorizing credentials use (SAD/R)

    EW->>+RS: /signatures/signHash
    RS->>-EW: signature

    EW->>+SCA: "obtain signed document" (certificates & document & signature value)
    SCA->>-EW: signed document
```

## Endpoints

### Calculate Hash Endpoint

* Method: POST
* URL: http://localhost:8086/signatures/calculate_hash

This endpoint calculates the digest value of a given document.
The payload of this request is a JSON object with the following attributes:
* **documents**: a JSON array consisting of JSON objects, where each object contains a base64-encoded document content to be signed and additional request parameters.
* **endEntityCertificate**: the base64-encoded certificate of the user.
* **certificateChain**: a list of base64-encoded certificates representing the certificate chain to be used when calculating the digest value, excluding the end-entity certificate.
* **hashAlgorithmOID**: the OID of the hash algorithm used to generate the digest value.

The endpoint should return a JSON object with the following attributes:
* **hashes**: a list of strings containing one or more BASE64 URL-encoded hash values to be signed.
* **signature_date**: the date of the signature request, as a long integer, which will be used later when obtaining the signed document.

### Obtain Signed Document Endpoint

* Method: POST
* URL: http://localhost:8086/signatures/obtain_signed_doc

This endpoint retrieves the signed document, given the document to be signed and the signature value.
The payload of this request is a JSON object with the following attributes:
* **documents**: a JSON array consisting of JSON objects, where each object contains a base64-encoded document content to be signed and additional request parameters.
* **endEntityCertificate**: the base64-encoded certificate of the user.
* **certificateChain**: a list of base64-encoded certificates representing the certificate chain to be used when calculating the digest value, excluding the end-entity certificate.
* **hashAlgorithmOID**: the OID of the hash algorithm used to generate the digest value.
* **returnValidationInfo**: a boolean indicating whether the server should return validation information (OCSP, CRL, or certificates).
* **date**: the value of 'signature_date' received in the response of 'calculate_hash' endpoint.
* **signatures**: the base64-encoded signature value of the document's digest.

The endpoint returns a JSON object with the following attributes:
* **documentWithSignature**: a base64-encoded signed document .
* **signatureObject**: the signature string received in the request.

## Deployment

### Requirements
* Java version 17
* Apache Maven 3.6.3

### Signature Creation Application

1. **Add the Timestamp Authority Information**

   For certain conformance levels, access to a Timestamp Authority is required.
   The Timestamp Authority to be used can be specified in the **application.yml** file located in the folder **src/main/resources/application.yml**.
       
    ```
    timestamp-authority:
        filename: # the path to the certificate of the Timestamp Authority chosen
        server-url: # the url of the Timestamp Authority
        supported-digest-algorithm: # the list of the digest algorithms that are supported by the TSA.
        - "2.16.840.1.101.3.4.2.1"
   ```

2. **Run the Resource Server**
   
    After configuring the previously mentioned settings and run the script:
   ```
   ./deploy_sca.sh
   ```

## How to contribute

We welcome contributions to this project. To ensure that the process is smooth for everyone
involved, follow the guidelines found in [CONTRIBUTING.md](CONTRIBUTING.md).

## License

### Third-party component licenses

See [licenses.md](licenses.md) for details.

### License details

Copyright (c) 2024 European Commission

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
