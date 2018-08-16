---
title: "ACME TLS ALPN Challenge Extension"
abbrev: ACME-TLS-ALPN
docname: draft-ietf-acme-tls-alpn-latest
category: std

ipr: trust200902
area: General
workgroup: ACME Working Group

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: R. B. Shoemaker
    name: Roland Bracewell Shoemaker
    org: Internet Security Research Group
    abbrev: ISRG
    email: roland@letsencrypt.org

normative:
  RFC2119:
  RFC3492:
  RFC4343:
  RFC5280:
  RFC6066:
  RFC7301:
  I-D.ietf-acme-acme:
  FIPS180-4:
    title: NIST FIPS 180-4, Secure Hash Standard
    author:
      name: NIST
      ins: National Institute of Standards and Technology, U.S. Department of Commerce
    date: 2012-03
    target: http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf

--- abstract

This document specifies a new challenge for the Automated Certificate Management Environment (ACME) protocol which allows for domain control validation using TLS.

--- middle

# Introduction

The Automatic Certificate Management Environment (ACME) {{I-D.ietf-acme-acme}} standard specifies methods for validating control of domain names via HTTP and DNS. Deployment experience has shown it is also useful to be able to validate domain control using the TLS layer alone. In particular, this allows hosting providers, CDNs, and TLS-terminating load balancers to validate domain control without modifying the HTTP handling behavior of their backends. This separation of layers can improve security and usability of ACME validation.

Early ACME drafts specified two TLS-based challenge types: TLS-SNI-01 and TLS-SNI-02. These methods were removed because they relied on assumptions about the deployed base of HTTPS hosting providers that proved to be incorrect. Those incorrect assumptions weakened the security of those methods and are discussed in the "Design Rationale" appendix.

This document specifies a new TLS-based challenge type, TLS-ALPN-01. This challenge requires negotiating a new application-layer protocol using the TLS Application-Layer Protocol Negotiation (ALPN) Extension {{!RFC7301}}. Because no existing software implements this protocol, the ability to fulfill TLS-ALPN-01 challenges is effectively opt-in. A service provider must proactively deploy new code in order to implement TLS-ALPN-01, so we can specify stronger controls in that code, resulting in a stronger validation method.

# Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 {{RFC2119}} {{!RFC8174}} when, and only when, they appear in all capitals, as shown here.

# TLS with Application Level Protocol Negotiation (TLS ALPN) Challenge

The TLS with Application Level Protocol Negotiation (TLS ALPN) validation method proves control over a domain name by requiring the client to configure a TLS server to respond to specific connection attempts utilizing the ALPN extension with identifying information. The ACME server validates control of the domain name by connecting to a TLS server at one of the addresses resolved for the domain name and verifying that a certificate with specific content is presented.

type (required, string):
: The string "tls-alpn-01"

token (required, string):
: A random value that uniquely identifies the challenge. This value MUST have at least 128 bits of entropy. It MUST NOT contain any characters outside the base64url alphabet, including padding characters ("="). See {{!RFC4086}} for additional information on randomness requirements.

~~~~~~~~~~
GET /acme/authz/1234/1 HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
{
  "type": "tls-alpn-01",
  "url": "https://example.com/acme/authz/1234/1",
  "status": "pending",
  "token": "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA"
}
~~~~~~~~~~

The client prepares for validation by constructing a self-signed certificate which MUST contain a acmeIdentifier extension and a subjectAlternativeName extension {{!RFC5280}}. The subjectAlternativeName extension MUST contain a single dNSName entry where the value is the domain name being validated. The acmeIdentifier extension MUST contain the SHA-256 digest [FIPS180-4] of the key authorization {{I-D.ietf-acme-acme}} for the challenge. The acmeIdentifier extension MUST be critical so that the certificate isn't inadvertently used by non-ACME software.

The acmeIdentifier extension has the following format:

~~~~~~~~~~
id-pe-acmeIdentifier OBJECT IDENTIFIER ::=  { id-pe 31 }

Authorization ::= OCTET STRING (SIZE (32))
~~~~~~~~~~

The extnValue of the id-pe-acmeIdentifier extension is the ASN.1 DER encoding of the Authorization structure, which contains the SHA-256 digest of the key authorization for the challenge.

Once this certificate has been created it MUST be provisioned such that it is returned during a TLS handshake that contains a ALPN extension containing the value "acme-tls/1" and a SNI extension containing the domain name being validated.

A client responds with an empty object ({}) to acknowledge that the challenge is ready to be validated by the server. The base64url encoding of the protected headers and payload is described in {{I-D.ietf-acme-acme}} Section 6.1.

~~~~~~~~~~
POST /acme/authz/1234/1
Host: example.com
Content-Type: application/jose+json

{
  "protected": base64url({
    "alg": "ES256",
    "kid": "https://example.com/acme/acct/1",
    "nonce": "JHb54aT_KTXBWQOzGYkt9A",
    "url": "https://example.com/acme/authz/1234/1"
  }),
  "payload": base64url({}),
  "signature": "Q1bURgJoEslbD1c5...3pYdSMLio57mQNN4"
}
~~~~~~~~~~


On receiving a response the server constructs and stores the key authorization from the challenge "token" value and the current client account key.

The server then verifies the client's control over the domain by verifying that the TLS server was configured as expected using the following steps:

1. Compute the expected SHA-256 digest of the expected key authorization.
2. Resolve the domain name being validated and choose one of the IP addresses returned for validation (the server MAY validate against multiple addresses if more than one is returned, but this is not required).
2. Initiate a TLS connection with the chosen IP address, this connection MUST use TCP port 443. The ClientHello that initiates the handshake MUST contain a ALPN extension with the single protocol name "acme-tls/1" and a Server Name Indication {{!RFC6066}} extension containing the domain name being validated.
3. Verify that the ServerHello contains a ALPN extension containing the value "acme-tls/1" and that the certificate returned contains a subjectAltName extension containing the dNSName being validated and no other entries and a critical acmeIdentifier extension containing the digest computed in step 1. The comparison of dNSNames MUST be case insensitive {{!RFC4343}}. Note that as ACME doesn't support Unicode identifiers all dNSNames MUST be encoded using the {{!RFC3492}} rules.

If all of the above steps succeed then the validation is successful, otherwise it fails. Once the TLS handshake has been completed the connection MUST be immediately closed and no further data should be exchanged.

## acme-tls/1 Protocol Definition

The "acme-tls/1" protocol MUST only be used for validating ACME tls-alpn-01 challenges. The protocol consists of a TLS handshake in which the required validation information is transmitted. Once the handshake is completed the client MUST NOT exchange any further data with the server and MUST immediately close the connection.

# Security Considerations

The design of this challenges relies on some assumptions centered around how a server behaves during validation.

The first assumption is that when a server is being used to serve content for multiple DNS names from a single IP address that it properly segregates control of those names to the users that own them. This means that if User A registers Host A and User B registers Host B the server should not allow a TLS request using a SNI value for Host A to be served by User B or Host B to be served by User A. If the server allows User B to serve this request it allows them to illegitimately validate control of Host A to the ACME server.

The second assumption is that a server will not violate {{!RFC7301}} by blindly agreeing to use the "acme-tls/1" protocol without actually understanding it.

To further mitigate the risk of users claiming domain names used by other users on the same infrastructure hosting providers, CDNs, and other service providers should not allow users to provide their own certificates for the TLS ALPN validation process. If providers wish to implement TLS ALPN validation they SHOULD only generate certificates used for validation themselves and not expose this functionality to users.

# IANA Considerations

[[RFC Editor: please replace XXXX below by the RFC number.]]

## SMI Security for PKIX Certificate Extension OID

Within the SMI-numbers registry, the "SMI Security for PKIX Certificate Extension (1.3.6.1.5.5.7.1)" table is to be updated to add the following entry:

| Decimal  | Description          | References |
|:---------|:---------------------|:-----------|
| 31       | id-pe-acmeIdentifier | RFC XXXX   |

## ALPN Protocol ID

Within the Transport Layer Security (TLS) Extensions registry, the "Application-Layer Protocol Negotiation (ALPN) Protocol IDs" table is to be updated to add the following entry:

| Protocol   | Identification Sequence                                          | Reference  |
|:-----------|:-----------------------------------------------------------------|:-----------|
| ACME-TLS/1 | 0x61 0x63 0x6d 0x65 0x2d 0x74 0x6c 0x73 0x2f 0x31 ("acme-tls/1") | RFC XXXX   |

## ACME Validation Method

The "ACME Validation Methods" registry is to be updated to include the following entry:

| Label       | Identifier Type | Reference |
|:------------|:----------------|:----------|
| tls-alpn-01 | dns             | RFC XXXX  |

# Appendix: Design Rationale

The TLS ALPN challenge exists to replace the TLS SNI challenge defined in the early ACME drafts. This challenge was convenient for service providers who were either operating large TLS layer load balancing systems at which they wanted to perform validation or running servers fronting large numbers of DNS names from a single host as it allowed validation purely within the TLS layer.

A security issue was discovered in the TLS SNI challenge by Frans Rosen which allowed users of various service providers to illegitimately validate control of the DNS names of other users of the provider. When the TLS SNI challenge was designed it was assumed that a user would only be able to respond to TLS traffic via SNI for domain names they controlled (i.e. if User A registered Host A and User B registered Host B with a service provider that User A wouldn't be able to respond to SNI traffic for Host B). This turns out not to be a security property provided by a number of large service providers. Because of this users were able to respond to SNI traffic for the SNI names used by the TLS SNI challenge validation process. This meant that if User A and User B had registered Host A and Host B respectively User A would be able to claim the SNI name for a validation for Host B and when the validation connection was made that User A would be able to answer, proving control of Host B.

# Acknowledgements

The author would like to thank all those whom have provided design insights and editorial review of this document, including Richard Barnes, Ryan Hurst, Adam Langley, Ryan Sleevi, Jacob Hoffman-Andrews, Daniel McCarney, Marcin Walas, and Martin Thomson and especially Frans Rosén who discovered the vulnerability in the TLS SNI method which necessitated the writing of this specication.
