---
title: PostQuantum algorithms in ZRTP Media Path Key Agreement for Unicast Secure RTP
abbrev: PQ Algoritms in ZRTP
docname: draft-zrtp-pq-latest

ipr: trust200902
submissiontype: independent
area: Internet
wg:
kw: Internet-Draft
cat: info
stand_alone: true

pi:    # can use array (if all yes) or hash here
  toc: yes
  sortrefs:   # defaults to yes
  symrefs: yes

author:
      -
        ins: P. Zimmermann
        name: Philip Zimmermann
        org: Silent Circle
        email: prz@mit.edu

      -
        ins: J. Pascal
        name: Johan Pascal
        org: Belledonne Communications
        email: johan.pascal@linphone.org

      -
        ins: L. Ferreira
        name: Lo&#239;c Ferreira
        org: Orange
        email: loic.ferreira@orange.com


contributor:

normative:
   RFC6189:
   RFC3550:
   RFC3261:
   RFC3711:
   RFC2119:
   RFC9180:
   RFC5869:
   RFC7748:
   RFC3526:
   RFC5114:
   RFC5479:
   RFC7983:
   RFC1191:
   RFC1981:

informative:
   NIST-PQC:
      title: "NIST Post-Quantum Cryptography Standardization"
      target: "https://csrc.nist.gov/Projects/post-quantum-cryptography/post-quantum-cryptography-standardization"
      date: "2017"

   NIST-SP800-56A:
      title: "Recommendation for Pair-Wise Key Establishment Schemes Using Discrete Logarithm Cryptography"
      target: "https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final"
      date: "April 2018"

   NIST-SP800-108:
      title: "Recommendation for Key Derivation Using Pseudorandom Functions (Revised)"
      target: "https://csrc.nist.gov/publications/detail/sp/800-108/final"
      date: "October 2009"

   NIST-FIPS180-4:
      title: "Secure Hash Standard (SHS)"
      target: "https://csrc.nist.gov/publications/detail/fips/180/4/final"
      date: "August 2015"

   NIST-FIPS202:
      title: "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions"
      target: "https://csrc.nist.gov/publications/detail/fips/202/final"
      date: "August 2015"

   NIST-FIPS186-5:
      title: "Digital Signature Standard (DSS)"
      target: "https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5-draft.pdf"
      date: "October 2019"

   NIST-SP800-186:
      title: "Recommendations for Discrete Logarithm-Based Cryptography: Elliptic Curve Domain Parameters"
      target: "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186-draft.pdf"
      date: "October 2019"

   Ber14:
      title: "Curve41417: Karatsuba revisited"
      target: "https://cr.yp.to/ecdh/curve41417-20140706.pdf"
      date: "2014"
      author:
         -
          ins: D.J. Bernstein
          name: Daniel J. Bernstein
         -
          ins: C. Chuengsatiansup
          name: Chitchanok Chuengsatiansup
         -
          ins: T. Lange
          name: Tanja Lange

   Bin18:
      title: "Hybrid Key Encapsulation Mechanisms and Authenticated Key Exchange"
      target: "https://eprint.iacr.org/2018/903.pdf"
      date: "2018"
      author:
         -
          ins: N. Bindel
          name: Nina Bindel
         -
          ins: J. Brendel
          name: Jacqueline Brendel
         -
          ins: M. Fischlin
          name: Marc Fischlin
         -
          ins: B. Goncalves
          name: Brian Goncalves
         -
          ins: D. Stebila
          name: Douglas Stebila

--- abstract

TODO
--- middle

# Introduction

ZRTP {{RFC6189}} is a key agreement protocol that performs a Diffie-Hellman (DH) key exchange during call setup in the media path and is transported over the same port as the Real-time Transport Protocol (RTP) {{RFC3550}} media stream which has been established using a signaling protocol such as Session Initiation Protocol (SIP) {{RFC3261}}.  This generates a shared secret, which is then used to generate keys and salt for a Secure RTP (SRTP) {{RFC3711}} session.

ZRTP design is based on the DH key exchange. The NIST Post-Quantum Cryptography Standardization {{NIST-PQC}} process requests the key exchange algorithms to use a Key Encapsulation Mechanism (KEM) API. The KEM form of a key exchange cannot substitute straightforwardly the DH key exchange used in ZRTP. In order to support Post-Quantum Key Exchange as defined in the NIST standardization process, a new Key Agreement Mode is introduced in ZRTP: KEM Mode.

Post-Quantum Key exchange algorithms are still in early stage of analysis and a common approch in their usage is to combine them with established algorithm. This is referred in this document as hybrid-KEM. In order to simplify the protocol, the hybrid mode is defined as a combination of two key exchange algorithms in KEM format. To this end, a definition of ECDH-based KEM similar to the one defined in Section 4.1 in {{RFC9180}} is given. The ECDH-based KEM is then combined with a PQ KEM to provide an hybrid KEM using the same public interface than a simple KEM.

Post-Quantum Key exchange may produce large public values to be exchanged with the other endpoint. UDP datagrams are often limited to \<1500 bytes if fragmentation is not desired. In order to compensate for this limitation ZRTP message may be fragmented over several ZRTP packets.

# Terminology {#Terminology}

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in {{RFC2119}}.

In this document, a "call" is synonymous with a "session".

A \|\| B denotes the concatenation of byte sequences A and B.

# Overview {#Overview}

## Key Agreement Modes

After both endpoints exchange Hello and HelloACK messages, the key agreement exchange can begin with the ZRTP Commit message.  ZRTP supports a number of key agreement modes including DH, KEM, PreShared or Multistream modes as described in the following sections.

The Commit message may be sent immediately after both endpoints have completed the Hello/HelloACK discovery handshake, or it may be deferred until later in the call, after the participants engage in some unencrypted conversation.  The Commit message may be manually activated by a user interface element, such as a GO SECURE button, which becomes enabled after the Hello/HelloACK discovery phase.  This emulates the user experience of a number of secure phones in the Public Switched Telephone Network (PSTN) world.  However, it is expected that most simple ZRTP user agents will omit such buttons and proceed directly to secure mode by sending a Commit message immediately after the Hello/HelloACK handshake.

### DH and KEM Modes

Examples ZRTP call flow are shown in {{FigDHCallFlow}} and {{FigKemCallFlow}}.  Note that the order of the Hello/HelloACK exchanges in F1/F2 and F3/F4 may be reversed.  That is, either Alice or Bob might send the first Hello message.  Note that the endpoint that sends the Commit message is considered the initiator of the ZRTP session and drives the key agreement exchange.

ZRTP authentication uses a Short Authentication String (SAS), which is ideally displayed for the human user.  Alternatively, the SAS can be authenticated by exchanging an optional digital signature (sig) over the SAS in the Confirm1 or Confirm2 messages (described in {{signingSASsec}}).

The ZRTP Confirm1 and Confirm2 messages are sent for a number of reasons, not the least of which is that they confirm that all the key agreement calculations were successful and thus the encryption will work.  They also carry other information such as the Disclosure flag (D), the Allow Clear flag (A), the SAS Verified flag (V), and the Private Branch Exchange (PBX) Enrollment flag (E).  All flags are encrypted to shield them from a passive observer.

#### DH Mode Overview

The DH public values are exchanged in the DHPart1 and DHPart2 messages.  SRTP keys and salts are then calculated.

The initiator needs to generate its ephemeral key pair before sending the Commit, and the responder generates its key pair before sending DHPart1.

~~~~~~~~~~

 Alice                                                Bob
    |                                                   |
    |      Alice and Bob establish a media session.     |
    |         They initiate ZRTP on media ports         |
    |                                                   |
    | F1 Hello (version, options, Alice's ZID)          |
    |-------------------------------------------------->|
    |                                       HelloACK F2 |
    |<--------------------------------------------------|
    |            Hello (version, options, Bob's ZID) F3 |
    |<--------------------------------------------------|
    | F4 HelloACK                                       |
    |-------------------------------------------------->|
    |                                                   |
    |             Bob acts as the initiator.            |
    |                                                   |
    |        Commit (Bob's ZID, options, hash value) F5 |
    |<--------------------------------------------------|
    | F6 DHPart1 (pvr, shared secret hashes)            |
    |-------------------------------------------------->|
    |            DHPart2 (pvi, shared secret hashes) F7 |
    |<--------------------------------------------------|
    |                                                   |
    |     Alice and Bob generate SRTP session key.      |
    |                                                   |
    | F8 Confirm1 (MAC, D,A,V,E flags, sig)             |
    |-------------------------------------------------->|
    |             Confirm2 (MAC, D,A,V,E flags, sig) F9 |
    |<--------------------------------------------------|
    | F10 Conf2ACK                                      |
    |-------------------------------------------------->|
    |                    SRTP begins                    |
    |<=================================================>|
    |                                                   |
~~~~~~~~~~
{: #FigDHCallFlow title="Establishment of an SRTP Session using ZRTP - DH mode"}

#### KEM Mode Overview

The KEM public values (public key  and ciphertext) are exchanged in the Commit and KEMPart1 messages. SRTP keys and salts are then calculated.

The initiator generates its ephemeral key pair (pvi,sk) and a random nonce before sending the Commit. He sends the public key (pvi) in the Commit message and the random nonce (ni) in the KEMPart2 message.

The responder generates and encapsulates the shared secret using the initiator public key (pvi) and send his ciphertext (pvr) in the KEMPart1 message.

~~~~~~~~~~

  Alice                                                Bob
    |                                                   |
    |      Alice and Bob establish a media session.     |
    |         They initiate ZRTP on media ports         |
    |                                                   |
    | F1 Hello (version, options, Alice's ZID)          |
    |-------------------------------------------------->|
    |                                       HelloACK F2 |
    |<--------------------------------------------------|
    |            Hello (version, options, Bob's ZID) F3 |
    |<--------------------------------------------------|
    | F4 HelloACK                                       |
    |-------------------------------------------------->|
    |                                                   |
    |             Bob acts as the initiator.            |
    |                                                   |
    |   Commit (Bob's ZID, options, hash value, pvi) F5 |
    |<--------------------------------------------------|
    | F6 KEMPart1 (pvr, shared secret hashes)           |
    |-------------------------------------------------->|
    |            KEMPart2 (ni, shared secret hashes) F7 |
    |<--------------------------------------------------|
    |                                                   |
    |     Alice and Bob generate SRTP session key.      |
    |                                                   |
    | F8 Confirm1 (MAC, D,A,V,E flags, sig)             |
    |-------------------------------------------------->|
    |             Confirm2 (MAC, D,A,V,E flags, sig) F9 |
    |<--------------------------------------------------|
    | F10 Conf2ACK                                      |
    |-------------------------------------------------->|
    |                    SRTP begins                    |
    |<=================================================>|
    |                                                   |
~~~~~~~~~~
{: #FigKemCallFlow title="Establishment of an SRTP Session using ZRTP - KEM mode"}

### Preshared Mode Overview

In the Preshared mode, endpoints can skip the DH calculation if they have a shared secret from a previous ZRTP session.  Preshared mode is indicated in the Commit message and results in the same call flow as Multistream mode.  The principal difference between Multistream mode and Preshared mode is that Preshared mode uses a previously cached shared secret, rs1, instead of an active ZRTP Session key as the initial keying material.

This mode could be useful for slow processor endpoints so that a DH calculation does not need to be performed every session.  Or, this mode could be used to rapidly re-establish an earlier session that was recently torn down or interrupted without the need to perform another DH calculation.

Preshared mode has forward secrecy properties.  If a phone's cache is captured by an opponent, the cached shared secrets cannot be used to recover earlier encrypted calls, because the shared secrets are replaced with new ones in each new call, as in DH mode.  However, the captured secrets can be used by a passive wiretapper in the media path to decrypt the next call, if the next call is in Preshared mode.  This differs from DH mode, which requires an active MiTM wiretapper to exploit captured secrets in the next call.  However, if the next call is missed by the wiretapper, he cannot wiretap any further calls.  Thus, it preserves most of the self-healing properties ({{SelfHealingKeyContinuityFeatureSec}}) of key continuity enjoyed by DH mode.

### Multistream Mode Overview

Multistream mode is an alternative key agreement method used when two endpoints have an established SRTP media stream between them with an active ZRTP Session key.  ZRTP can derive multiple SRTP keys from a single DH exchange.  For example, an established secure voice call that adds a video stream uses Multistream mode to quickly initiate the video stream without a second DH exchange.

When Multistream mode is indicated in the Commit message, a call flow similar to Figure 1 is used, but no DH calculation is performed by either endpoint and the DHPart1 and DHPart2 messages are omitted.  The Confirm1, Confirm2, and Conf2ACK messages are still sent.  Since the cache is not affected during this mode, multiple Multistream ZRTP exchanges can be performed in parallel between two endpoints.

# Protocol Description

## Discovery {#DiscoverySec}

### Protocol Version Negotiation

### Algorithm Negotiation {#AlgorithmNegotiationSec}

Each Hello message lists the algorithms in the order of preference for that ZRTP endpoint.  Endpoints eliminate the non-intersecting choices from each of their own lists, resulting in each endpoint having a list of algorithms in common that might or might not be ordered the same as the other endpoint's list.

Unfavorable choices will never be made by this method, because each endpoint will omit from their respective lists choices that are too slow or not secure enough to meet their security policy.

#### Key Agreement Algorithm

##### DH Mode Only

A method is provided to allow the two parties to mutually and deterministically choose the same DH key size and algorithm before a Commit message is sent.

After removing non intersecting algorithms from the Hello message lists, each endpoint compares the first item on their own list with the first item on the other endpoint's list and SHOULD choose the faster of the two algorithms.  For example:

* Alice's full list: DH2k, DH3k, EC25
* Bob's full list: EC38, EC25, DH3k
* Alice's intersecting list: DH3k, EC25
* Bob's intersecting list: EC25, DH3k
* Alice's first choice is DH3k, and Bob's first choice is EC25.
* Thus, both parties choose EC25 (ECDH-256) because it's faster.

To decide which DH algorithm is faster, the following ranking, from fastest to slowest is defined: DH-2048, X25519, ECDH-256, DH-3072, ECDH-384, X41417, X448, ECDH-521. These are all defined in {{keyAgreementTypeBlock}}.

If both endpoints follow this method, they may each start their DH calculations as soon as they receive the Hello message, and there will be no need for either endpoint to discard their DH calculation if the other endpoint becomes the initiator.

##### KEM Mode Only

The initiator simply selects any key agreement from the algorithms in common.

##### DH and KEM Mixed in Hello Message Key Agreement List

When both KEM and DH algorithms end up in the common ordered algo lists.

* If Alice's and Bob's intersecting list first algorithm is a KEM, the KEM Mode only selection applies.
* If Alice's and Bob's intersecting list first algorithm is a DH, KEM algos are dropped from the lists and the DH Mode only selection applies.
* If one is DH and the other is KEM, the DH algorithm is selected.

Example:

* Alice's full list: X25519, X25519+Kyber512, X448
* Bob's full list: X25519+Kyber512, X25519
* Alice's intersecting list: X25519, X25519+Kyber512
* Bob's intersecting list: X25519+Kyber512, X25519
* Alice's first choice is a DH algorithn (X25519), and Bob's first choice is KEM algorithm (X25519+Kyber512).
* Thus, both parties choose X25519.

Example:

* Alice's full list: X448, X25519, X25519+Kyber512, DH3k
* Bob's full list: DH3k, X25519+Kyber512, X25519
* Alice's intersecting list: X25519, X25519+Kyber512, DH3k
* Bob's intersecting list: DH3k, X25519+Kyber512, X25519
* Alice's first choice is a DH algorithn (X25519), and Bob's first choice is DH algorithm (DH3k): drop X25519+Kyber512 from the intersecting lists.
* Thus, both parties choose X25519 because it is faster than DH3k.

Example:

* Alice's full list: X448+Kyber1024, X25519+Kyber512, X448, X25519
* Bob's full list: X25519+Kyber512, X448+Kyber1024, X25519
* Alice's intersecting list: X448+Kyber1024, X25519+Kyber512, X25519
* Bob's intersecting list: X25519+Kyber512, X448+kyber1024, X25519
* Alice's first choice is a KEM algorithn (X448+Kyber1024), and Bob's first choice is KEM algorithm (X25519+Kyber512).
* The initiator chooses X448+Kyber1024 because it provides a higher security level

#### Other Algorithms

For the rest of the algorithm choices, it is simply whatever the initiator selects from the algorithms in common. Note that the DH or KEM key size influences the Hash Type and the size of the symmetric cipher key, as explained in {{keyAgreementTypeBlock}}.


## Commit Contention

## Matching Shared Secret Determination {#MatchingSharedSecretDeterminationSec}

### Calculation and Comparison of Hashes of Shared Secrets {#CalculationAndComparisonOfHashesSharedSecretsSec}

### Handling a Shared Secret Cache Mismatch

## Key Agreements
The next step is the generation of a secret for deriving SRTP keying material.  ZRTP uses for modes: DH, KEM, PreShared and Multistream, described in the following subsections.

### DH and KEM Modes {#DHandKEMModesSec}

The purpose of the key exchange is for the two ZRTP endpoints to generate a new shared secret, s0.  In addition, the endpoints discover if they have any cached or previously stored shared secrets in common, and they use them as part of the calculation of the session keys.
Because the key exchange affects the state of the retained shared secret cache, only one in-process ZRTP key exchange may occur at a time between two ZRTP endpoints.  Otherwise, race conditions and cache integrity problems will result.  When multiple media streams are established in parallel between the same pair of ZRTP endpoints (determined by the ZIDs in the Hello messages), only one can be processed.  Once that exchange completes with Confirm2 and Conf2ACK messages, another ZRTP key exchange can begin.  This constraint does not apply when Multistream mode key agreement is used since the cached shared secrets are not affected.

From the intersection of the algorithms in the sent and received Hello messages, the initiator chooses a hash, cipher, auth tag, Key Agreement Type, and SAS Type to be used.

#### DH Mode

##### Hash Commitment in DH Mode

A DH mode is selected by setting the Key Agreement Type in the Commit to one of the DH or Elliptic Curve Diffie-Hellman (ECDH) values from the table in {{keyAgreementTypeBlock}}.  In this mode, the key agreement begins with the initiator choosing a fresh random DH secret value (svi) based on the chosen Key Agreement Type value, and computing the public value.  (Note that to speed up processing, this computation can be done in advance.)  For guidance on generating random numbers, see {{RandomNumbersSec}}.

For Finite Field DH, the value for the DH generator g, the DH prime p, and the length of the DH secret value, svi, are defined in {{keyAgreementTypeBlock}}.

      pvi = g^svi mod p

where g and p are determined by the Key Agreement Type value. The DH public value pvi value is formatted as a big-endian octet string and fixed to the bit-length of the DH prime; leading zeros MUST NOT be truncated.

For Elliptic Curve DH, pvi is calculated and formatted according to the ECDH specification in {{keyAgreementTypeBlock}}, which refers in detail to certain sections of {{NIST-SP800-56A}}.

The hash commitment is performed by the initiator of the ZRTP exchange. The hash value of the initiator, hvi, includes a hash of the entire DHPart2 message as shown in {{FigDHPart2Message}} (which includes the DH public value, pvi), and the responder's Hello message.  The hvi hash is truncated to 256 bits:

~~~
hvi = hash(initiator's DHPart2 message || responder's Hello message)
~~~

Note that the Hello message includes the fields shown in {{FigHelloMessage}}.

The information from the responder's Hello message is included in the hash calculation to prevent a bid-down attack by modification of the responder's Hello message.

The initiator sends the hvi in the Commit message.

The use of hash commitment in the DH exchange constrains the attacker to only one guess to generate the correct Short Authentication String (SAS) ({{SASSec}}) in his attack, which means the SAS can be quite short.  A 16-bit SAS, for example, provides the attacker only one chance out of 65536 of not being detected.  Without this hash commitment feature, a MiTM attacker would acquire both the pvi and pvr public values from the two parties before having to choose his own two DH public values for his MiTM attack.  He could then use that information to quickly perform a bunch of trial DH calculations for both sides until he finds two with a matching SAS.  To raise the cost of this birthday attack, the SAS would have to be much longer.  The Short Authentication String would have to become a Long Authentication String, which would be unacceptable to the user.  A hash commitment precludes this attack by forcing the MiTM to choose his own two DH public values before learning the public values of either of the two parties.

##### Responder Behavior in DH Mode

Upon receipt of the Commit message, the responder generates its own fresh random DH secret value, svr, and computes the public value.  (Note that to speed up processing, this computation can be done in advance, with no need to discard this computation if both endpoints chose the same algorithm via {{AlgorithmNegotiationSec}}). For guidance on random number generation, see {{RandomNumbersSec}}.

For Finite Field DH, the value for the DH generator g, the DH prime p, and the length of the DH secret value, svr, are defined in {{keyAgreementTypeBlock}}.

pvr = g^svr mod p

The pvr value is formatted as a big-endian octet string, fixed to the bit-length of the DH prime; leading zeros MUST NOT be truncated.

For Elliptic Curve DH, pvr is calculated and formatted according to the ECDH specification in {{keyAgreementTypeBlock}}, which refers in detail to certain sections of {{NIST-SP800-56A}}.

Upon receipt of the DHPart2 message, the responder checks that the initiator's DH public value is not equal to 1 or p-1.  An attacker might inject a false DHPart2 message with a value of 1 or p-1 for g^svi mod p, which would cause a disastrously weak final DH result to be computed.  If pvi is 1 or p-1, the user SHOULD be alerted of the attack and the protocol exchange MUST be terminated.  Otherwise, the responder computes its own value for the hash commitment using the DH public value (pvi) received in the DHPart2 message and its own Hello message and compares the result with the hvi received in the Commit message.  If they are different, a MiTM attack is taking place and the user is alerted and the protocol exchange terminated.

The responder then calculates the DH result:

DHResult = pvi^svr mod p

##### Initiator Behavior in DH Mode

Upon receipt of the DHPart1 message, the initiator checks that the responder's DH public value is not equal to 1 or p-1.  An attacker might inject a false DHPart1 message with a value of 1 or p-1 for g^svr mod p, which would cause a disastrously weak final DH result to be computed.  If pvr is 1 or p-1, the user should be alerted of the attack and the protocol exchange MUST be terminated.

The initiator then sends a DHPart2 message containing the initiator's DH public value and the set of calculated shared secret IDs as defined in {{CalculationAndComparisonOfHashesSharedSecretsSec}}.

The initiator calculates the same DH result using:

DHResult = pvr^svi mod p

##### Key Exchange Result in DH Mode

For both the initiator and responder, the DHResult is formatted as a big-endian octet string and fixed to the width of the DH prime; leading zeros MUST NOT be truncated.  For example, for a 3072-bit p, DHResult would be a 384 octet value, with the first octet the most significant.  DHResult may also be the result of an ECDH calculation, which is discussed in {{keyAgreementTypeBlock}}.

----------------

| Key Agreement | Size of DHResult |
|---------------+------------------|
| DH-3072    | 384 octets |
|------------+------------|
| DH-2048    | 256 octets |
|------------+------------|
| ECDH P-256 |  32 octets |
|------------+------------|
| ECDH P-384 |  48 octets |
|------------+------------|
| ECDH X25519|  32 octets |
|------------+------------|
| ECDH X41417|  52 octets |
|------------+------------|
| ECDH X448  |  56 octets |
{: #DHResultSize title="DHResult size"}

#### KEM Mode

The KEM is based on an interface providing three functions:

* Generate a fresh set of key pair:

publicKey, secretKey = KEMgenKey()

* Generate a sharedSecret and encapsulates it in cipherText using the given publicKey:

sharedSecret, cipherText = KEMencaps( publicKey )

* Use the given secretKey to compute the sharedSecret encapsulated in cipherText:

sharedSecret = KEMdecaps( cipherText, secretKey )

This mode is used to support Post-Quantum algorithms defined with this interface imposed by the NIST Post-Quantum Cryptography Standardization process {{NIST-PQC}}.

##### Hash Commitment in KEM Mode

A KEM mode is selected by setting the Key Agreement Type in the Commit to one of the KEM values from the table in {{keyAgreementTypeBlock}}.  In this mode, the key agreement begins with the initiator generating a fresh random key pair (public key pvi and secret key svi) based on the chosen Key Agreement Type value and a 256-bit random nonce.  For guidance on generating random numbers, see {{RandomNumbersSec}}.

pvi,svi = KEMgenKey()

The generated public key (pvi) is inserted in the Commit message as shown in {{FigKEMCommitMessage}}, the random nonce (ni) is inserted in the KEMPart2 message which does not convey data directly related to the key exchange itself as shown in {{FigKEMPart2Message}}.

The hash commitment is performed by the initiator of the ZRTP exchange. The hash value of the initiator, hvi, includes a hash of the entire KEMPart2 message as shown in {{FigKEMPart2Message}} and the responder's Hello message. The hvi hash is truncated to 256 bits:

~~~
hvi = hash(initiator's KEMPart2 message || responder's Hello message)
~~~

Note that the Hello message includes the fields shown in {{FigHelloMessage}}.

The information from the responder's Hello message is included in the hash calculation to prevent a bid-down attack by modification of the responder's Hello message.

The initiator sends the hvi in the Commit message.

As detailed in {{SharedSecretCalculationSec}}, shared secret calculation in Key Exchange mode involves a transcript including Commit and KEMPart2 messages. The use of hash commitment constrains the attacker to only one guess to generate the correct Short Authentication String (SAS) ({{SASSec}}) in his attack, which means the SAS can be quite short.  A 16-bit SAS, for example, provides the attacker only one chance out of 65536 of not being detected.

Without the KEMPart2 message, a MitM putting itself in the role of responder could acquire pvi and quickly perform a bunch of trial encapsulations or modify the retained secrets ids until he finds a SAS mathing the one generated on the other connection. The KEMPart2 message forces the responder to wait for it to be able to derive the SAS even with the ability to select the shared secret exchanged via the KEM itself.

Without the hash commitment feature, a MitM putting itself in the role of initiator could acquire the pvr and quickly perform a bunch of trial SAS computation using random nonces (ni) and/or retained secret ids until he finds two matching SAS.

To raise the cost of this birthday attack, the SAS would have to be much longer.  The Short Authentication String would have to become a Long Authentication String, which would be unacceptable to the user.  KEMPart2 nonce and a hash commitment precludes this attack by forcing the MiTM to choose his own nonce before learning the other endpoint contribution to the final secret.


##### Responder Behavior in KEM Mode

Upon receipt of the Commit message, the responder uses the public key pvi to generate the shared secret, KEMResult and to encapsulate it in a public value pvr.

KEMResult, pvr = KEMencaps(pvi)

Upon receipt of the KEMPart2 message, the responder computes its own value for the hash commitment using the received KEMPart2 message and its own Hello message and compares the result with the hvi received in the Commit message.  If they are different, a MiTM attack is taking place and the user is alerted and the protocol exchange terminated.

##### Initiator Behavior in KEM Mode

Upon receipt of the KEMPart1 message, the initiator computes the same KEMResult using the decapsulation function on the responder's public value (pvr) and its own private key (svi)

KEMResult = KEMdecaps(pvr, svi)

The initiator then sends a KEMPart2 message containing the initiator's random nonce (ni) and the set of calculated shared secret IDs as defined in {{CalculationAndComparisonOfHashesSharedSecretsSec}}.

##### Key Exchange Result in KEM Mode

KEMResult size is defined by the algorithm used. See {{keyAgreementTypeBlock}} for details.

#### Shared Secret Calculation for DH and KEM Mode {#SharedSecretCalculationSec}

A hash of the received and sent ZRTP messages in the current ZRTP exchange in the following order is calculated by both parties:

~~~
total_hash = hash(Hello of initiator || Hello of responder || Commit
                 || DHPart1 || DHPart2)

or

total_hash = hash(Hello of initiator || Hello of responder || Commit
                 || KEMPart1 || KEMPart2)
~~~

Note that only the ZRTP messages not the entire ZRTP packets, are included in the total\_hash.

The result of the key exchange, being DHResult or KEMResult, is referred here to as KEResult. The authors believe the calculation of the final shared secret, s0, is in compliance with the recommendations in Sections 5.8.1 and 6.1.2.1 of {{NIST-SP800-56A}}.  This is done by hashing a concatenation of a number of items, including the KEResult, the ZID's of the initiator (ZIDi) and the responder (ZIDr), the total\_hash, and the set of non-null shared secrets as described in {{MatchingSharedSecretDeterminationSec}}.

In Section 5.8.1 of {{NIST-SP800-56A}}, NIST requires certain parameters to be hashed together in a particular order, which NIST refers to as: Z, AlgorithmID, PartyUInfo, PartyVInfo, SuppPubInfo, and SuppPrivInfo.  In our implementation, our KEResult corresponds to Z, "ZRTP-HMAC-KDF" corresponds to AlgorithmID, our ZIDi and ZIDr correspond to PartyUInfo and PartyVInfo, our total\_hash corresponds to SuppPubInfo, and the set of three shared secrets s1, s2, and s3 corresponds to SuppPrivInfo.  NIST also requires a 32-bit big-endian integer counter to be included in the hash each time the hash is computed, which we have set to the fixed value of 1 because we only compute the hash once.  NIST refers to the final hash output as DerivedKeyingMaterial, which corresponds to our s0 in this calculation.

~~~
s0 = hash(counter || KEResult || "ZRTP-HMAC-KDF"
         || ZIDi || ZIDr || total_hash
         || len(s1) || s1 || len(s2) || s2 || len(s3) || s3)
~~~

Note that temporary values s1, s2, and s3 were calculated per the methods described in {{MatchingSharedSecretDeterminationSec}}.  KEResult, s1, s2, and s3 MUST all be erased from memory immediately after they are used to calculate s0.

The length of the KEResult field was implicitly agreed to by the negotiated Key exchange algorithm.  The length of total\_hash is implicitly determined by the negotiated hash algorithm.  All of the explicit length fields, len(), in the above hash are 32-bit big-endian integers, giving the length in octets of the field that follows.  Some members of the set of shared secrets (s1, s2, and s3) may have lengths of zero if they are null (not shared) and are each preceded by a 4-octet length field.  For example, if s2 is null, len(s2) is 0x00000000, and s2 itself would be absent from the hash calculation, which means len(s3) would immediately follow len(s2).  While inclusion of ZIDi and ZIDr may be redundant, because they are implicitly included in the total\_hash, we explicitly include them here to follow {{NIST-SP800-56A}}.  The fixed-length string "ZRTP-HMAC- KDF" (not null-terminated) identifies for what purpose the resulting s0 will be used, which is to serve as the key derivation key for the ZRTP HMAC-based key derivation function (KDF) defined in {{TheZrtpKeyDerivationFunctionSec}} and used in {{DerivingTheRestOfTheKeysFromS0Sec}}.

The authors believe ZRTP Key exchange mode is in full compliance with two relevant NIST documents that cover key derivations.  First, Section 5.8.1 of {{NIST-SP800-56A}} computes what NIST refers to as DerivedKeyingMaterial, which ZRTP refers to as s0.  This s0 then serves as the key derivation key, which NIST refers to as KI in the key derivation function described in Sections 5 and 5.1 of {{NIST-SP800-108}}, to derive all the rest of the subkeys needed by ZRTP.

The ZRTP key derivation function (KDF) {{TheZrtpKeyDerivationFunctionSec}} requires the use of a KDF Context field (per {{NIST-SP800-108}} guidelines), which should include the ZIDi, ZIDr, and a nonce value known to both parties.  The total\_hash qualifies as a nonce value, because its computation included nonce material from the initiator's Commit message and the responder's Hello message.

~~~
KDF_Context = (ZIDi || ZIDr || total_hash)
~~~

At this point in DH or KEM mode, the two endpoints proceed to the key derivations of ZRTPSess and the rest of the keys in {{DerivingZRTPSessKeyAndSAS}}, now that there is a defined s0.

### PresharedMode

The Preshared key agreement mode can be used to generate SRTP keys and salts without a DH or KEM calculation, instead relying on a shared secret from previous DH or KEM calculations between the endpoints.

This key agreement mode is useful to rapidly re-establish a secure session between two parties who have recently started and ended a secure session that has already performed a DH or KEM key agreement, without performing another lengthy calculation, which may be desirable on slow processors in resource-limited environments.  Preshared mode MUST NOT be used for adding additional media streams to an existing call.  Multistream mode MUST be used for this purpose.

In the most severe resource-limited environments, Preshared mode may be useful with processors that cannot perform a DH or KEM calculation in an ergonomically acceptable time limit.  Shared key material may be manually provisioned between two such endpoints in advance and still allow a limited subset of functionality.  Such a "better than nothing" implementation would have to be regarded as non-compliant with the ZRTP specification, but it could interoperate in Preshared (and if applicable, Multistream) mode with a compliant ZRTP endpoint.

Because Preshared mode affects the state of the retained shared secret cache, only one in-process ZRTP Preshared exchange may occur at a time between two ZRTP endpoints.  This rule is explained in more detail in {{DHandKEMModesSec}}, and applies for the same reasons as in DH mode.

Preshared mode is only included in this specification to meet the R-REUSE requirement in the Media Security Requirements {{RFC5479}} document.  A series of preshared-keyed calls between two ZRTP endpoints should use a DH or KEM key exchange periodically.  Preshared mode is only used if a cached shared secret has been established in an earlier session by a DH or KEM exchange, as discussed in {{ZIDandCacheOperationSec}}.

### Multistream Mode

## Key Derivation

### The ZRTP Key Derivation Function {#TheZrtpKeyDerivationFunctionSec}

### Deriving ZRTPSess Key and SAS in Key Exchange or Preshared Modes {#DerivingZRTPSessKeyAndSAS}

### Deriving the Rest of the Keys from s0 {#DerivingTheRestOfTheKeysFromS0Sec}

## Confirmation

## Termination

## Random Number Generator {#RandomNumbersSec}

## ZID and Cache Operation {#ZIDandCacheOperationSec}

# ZRTP Packets

## ZRTP Packet Formats {#ZRTPPacketFormatsSec}

All ZRTP packets messages use the message format defined in {{FigNonFragmentedMessage}} and {{FigFragmentedMessage}}.  All word lengths referenced in this specification are 32 bits, or 4 octets.  All integer fields are carried in network byte order, that is, most-significant byte (octet) first, commonly known as big-endian.

~~~~~~~~~~
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0 0 0 1 0 0 0 0|  Not Used: 0  |         Sequence Number       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                 Magic Cookie 'ZRTP' (0x5a525450)              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Source Identifier                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |           ZRTP Message (length depends on Message Type)       |
   |                            . . .                              |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          CRC (1 word)                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~~~~~~~~
{: #FigNonFragmentedMessage title="Non Fragmented Message Packet Format"}

~~~~~~~~~~
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0 0 0 1 0 0 0 1|  Not Used: 0  |         Sequence Number       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                 Magic Cookie 'ZRTP' (0x5a525450)              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Source Identifier                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |            message Id         |    message total length       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |            offset             |    fragment length            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |           ZRTP Message fragment(length as indicated)          |
   |                            . . .                              |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          CRC (1 word)                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~~~~~~~~
{: #FigFragmentedMessage title="Fragmented Message Packet Format"}

{{RFC7983}} section 7 reserves for the ZRTP packet format the values 16 to 19 on the first byte to clearly distinguish ZRTP packets from STUN, DTLS, TURN or RTP/RTCP packets.
Values 16 and 17 are used to distinguish fragmented and non-fragmented messages. The 8 unused bits are set to zero and MUST be ignored when received. Previous version of ZRTP non supporting the message fragmentation will simply discard the fragmented message as invalid.

* The Sequence Number is a count that is incremented for each ZRTP packet sent.  The count is initialized to a random value.  This is useful in estimating ZRTP packet loss and also detecting when ZRTP packets arrive out of sequence.

* The ZRTP Magic Cookie is a 32-bit string that uniquely identifies a ZRTP packet and has the value 0x5a525450.

* Source Identifier is the SSRC number of the RTP stream to which this ZRTP packet relates.  For cases of forking or forwarding, RTP, and hence ZRTP, may arrive at the same port from several different sources -- each of these sources will have a different SSRC and may initiate an independent ZRTP protocol session.  SSRC collisions would be disruptive to ZRTP.  SSRC collision handling procedures are described in {{DiscoverySec}}.

When the packet carries a message fragment, the header also includes:

* message Id: a unique Id for this message, is attached to the message and is not incremented at each retransmission like the sequence number. It is initialised to a random value and is incremented for each new message generated.

* message total length: size, in 32-bit words of the total message.

* offset: offset of this fragment, in 32-bit words.

* fragment length: size of this fragment, in 32-bit words.

The messages susceptibles to be fragmented are Commit, KEMPart1, Confirm1 and Confirm2 messages. There is then no reason to store fragments for several messages. A simple buffer storing the message currently in reception is enough, if a fragment with message Id superior to the current one is received, the current buffer content must be discarded and the new message collection started. Fragments may overlap if the MTU is modified during the ZRTP handshake.

The ZRTP messages are defined in {{ZRTPMessageFormats}} and are of variable length.

## ZRTP Message Formats {#ZRTPMessageFormats}

### Message Type Block

### Hash Type Block {#HashTypeBlockSec}
----------------

|---
| Hash Type Block | Meaning |
|-----------------|:-------:|
| "S256" | SHA-256 Hash defined in {{NIST-FIPS180-4}} |
|---
| "S384" | SHA-384 Hash defined in {{NIST-FIPS180-4}} |
|---
| "S512" | SHA-512 Hash defined in {{NIST-FIPS180-4}} |
|---
| "N256" | SHA3-256 Hash defined in {{NIST-FIPS202}} |
|---
| "N384" | SHA3-384 Hash defined in {{NIST-FIPS202}} |
|---
| "N512" | SHA3-512 Hash defined in {{NIST-FIPS202}} |
|---
{: #HashTypeBlockValues title="Hash Type Block values"}

### Cipher Type Block

### Auth Tag Type Block

### Key Agreement Type Block {#keyAgreementTypeBlock}
----------------

|---
| Key Agreement Type Block | Short Type Block | Meaning |
|---------------|:-----------------------------:|
| "DH3k" | - | DH mode with p=3072 bit prime per {{RFC3526}}, Section 4. |
|---
| "DH2k" | - | DH mode with p=2048 bit prime per {{RFC3526}}, Section 3.|
|---
| "EC25" | - | Elliptic Curve DH, P-256 per {{RFC5114}}, Section 2.6 |
|---
| "EC38" | - | Elliptic Curve DH, P-384 per {{RFC5114}}, Section 2.7 |
|---
| "X255" | "X1" | ECDH X25519 per {{RFC7748}} |
|---
| "X414" | "X2" | ECDH 41417 per {{Ber14}} |
|---
| "X448" | "X3" | ECDH X448 per {{RFC7748}} |
|---
{: #KeyAgreementTypeBlockValuesDHMode title="Key Agreement Type Block values for DH Mode"}

|---
| Key Agreement Type Block | Short Type Block | Meaning |
|---------------|:-----------------------------:|
| "KYB1" | "K1" | Kyber512 |
|---
| "KYB2" | "K2" | Kyber768 |
|---
| "KYB3" | "K3" | Kyber1024 |
|---
| "BIK1" | "B1" | Bike-L1 |
|---
| "BIK2" | "B2" | Bike-L3 |
|---
| "BIK3" | "B3" | Bike-L5 |
|---
| "HQC1" | "H1" | HQC-128 |
|---
| "HQC2" | "H2" | HQC-192 |
|---
| "HQC3" | "H3" | HQC-256 |
|---
| "NTR1" | "N1" | NTRU-HPS 2048-509 |
|---
| "NTR2" | "N2" | NTRU-HPS 2048-677 |
|---
| "NTR3" | "N3" | NTRU-HPS 4096-821 |
|---
| "SAB1" | "A1" | LightSaber |
|---
| "SAB2" | "A2" | Saber |
|---
| "SAB3" | "A3" | FireSaber |
|---
{: #PostQuantumKeyAgreementTypeBlockValues title="Post Quantum Key Agreement Type Block values"}

|---
| Key Agreement Type Block | Meaning |
|---------------|:-------:|:---------:|:-----------------------------:|
| "Prsh" | Preshared Non-DH mode |
|---
| "Mult" | Multistream Non-DH mode |
|---
{: #KeyAgreementTypeBlockValuesPrshMult title="Key Agreement Type Block values for Preshared and Multistream mode"}

#### Hybrid KEM designation

The Hybrid KEM, constructed as decribed in {{HybridKEMSec}}, can combine several KEMs. It is recommended to use one ECDH algorithm(X25519, X41417 or X448) used in KEM form as described in {{ECHDBasedKEMSec}} and one or more of the PQ KEM from {{KeyAgreementTypeBlockValuesDHMode}}. The 4 characters char describing an hybrid KEM key agreement type block is built using the "Short Type Block" from {{KeyAgreementTypeBlockValuesDHMode}} and {{PostQuantumKeyAgreementTypeBlockValues}}. The ECDH-based KEM is always mentionned first.

For an hybrid scheme combining one ECDH and one PQ KEM, the key agreement type block concatenates the 2 short type blocks. Examples:

* X25519/Kyber512: "X1K1"

* X448/Saber: "X3A2"

* X41417/Bike-L3: "X2B3"

For an hybrid scheme combining one ECDH and two PQ KEM, the key agreement type block uses the short type blocks first letter and one number for the algorithm variation applied to the three algorithms involved. This limit the three parties hybrid to some combinations. Examples:

* X25519/Kyber512/HQC128: "XKH1"

* X448/Kyber1024/HQC256: "XKH3"

* X25519/Kyber1024/HQC192: impossible to produce using the described method.

### SAS Type Block

### Signature Type Block {#SignatureTypeBlockSec}

## Hello Message {#HelloMessageSec}


~~~~~~~~~~

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0 1 0 1 0 0 0 0 0 1 0 1 1 0 1 0|             length            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |            Message Type Block="Hello   " (2 words)            |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                   version="1.10" (1 word)                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                Client Identifier (4 words)                    |
   |                                                               |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                   Hash image H3 (8 words)                     |
   |                             . . .                             |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                         ZID  (3 words)                        |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|S|M|P| unused (zeros)|  hc   |  cc   |  ac   |  kc   |  sc   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                 hash algorithms (0 to 7 values)               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |               cipher algorithms (0 to 7 values)               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                  auth tag types (0 to 7 values)               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |               Key Agreement Types (0 to 7 values)             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    SAS Types (0 to 7 values)                  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         MAC (2 words)                         |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~~~~~~~~
{: #FigHelloMessage title="Hello Message Format"}

## HelloAck Message

## Commit Message

~~~~~~~~~~

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0 1 0 1 0 0 0 0 0 1 0 1 1 0 1 0|        length=29 words        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |              Message Type Block="Commit  " (2 words)          |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                   Hash image H2 (8 words)                     |
   |                             . . .                             |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                         ZID  (3 words)                        |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       hash algorithm                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      cipher algorithm                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       auth tag type                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Key Agreement Type                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         SAS Type                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                       hvi (8 words)                           |
   |                           . . .                               |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         MAC (2 words)                         |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

~~~~~~~~~~
{: #FigDHCommitMessage title="DH Commit Message Format"}

~~~~~~~~~~

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0 1 0 1 0 0 0 0 0 1 0 1 1 0 1 0|   length=depends on KA type   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |              Message Type Block="Commit  " (2 words)          |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                   Hash image H2 (8 words)                     |
   |                             . . .                             |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                         ZID  (3 words)                        |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       hash algorithm                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      cipher algorithm                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       auth tag type                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Key Agreement Type                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         SAS Type                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                       hvi (8 words)                           |
   |                           . . .                               |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                 pvi (length depends on KA Type)               |
   |                           . . .                               |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         MAC (2 words)                         |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

~~~~~~~~~~
{: #FigKEMCommitMessage title="KEM Commit Message Format"}

## DHPart1 Message

~~~~~~~~~~

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0 1 0 1 0 0 0 0 0 1 0 1 1 0 1 0|   length=depends on KA Type   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |              Message Type Block="DHPart1 " (2 words)          |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                   Hash image H1 (8 words)                     |
   |                             . . .                             |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        rs1IDr (2 words)                       |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        rs2IDr (2 words)                       |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     auxsecretIDr (2 words)                    |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     pbxsecretIDr (2 words)                    |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                  pvr (length depends on KA Type)              |
   |                               . . .                           |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         MAC (2 words)                         |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~~~~~~~~
{: #FigDHPart1Message title="DHPart1 Message Format"}

## DHPart2 Message


~~~~~~~~~~

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0 1 0 1 0 0 0 0 0 1 0 1 1 0 1 0|   length=depends on KA Type   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |              Message Type Block="DHPart2 " (2 words)          |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                   Hash image H1 (8 words)                     |
   |                             . . .                             |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        rs1IDi (2 words)                       |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        rs2IDi (2 words)                       |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     auxsecretIDi (2 words)                    |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     pbxsecretIDi (2 words)                    |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                  pvi (length depends on KA Type)              |
   |                               . . .                           |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         MAC (2 words)                         |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~~~~~~~~
{: #FigDHPart2Message title="DHPart2 Message Format"}

## KEMPart1 Message

~~~~~~~~~~

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0 1 0 1 0 0 0 0 0 1 0 1 1 0 1 0|   length=depends on KA Type   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |              Message Type Block="KEMPart1" (2 words)          |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                   Hash image H1 (8 words)                     |
   |                             . . .                             |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        rs1IDi (2 words)                       |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        rs2IDi (2 words)                       |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     auxsecretIDi (2 words)                    |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     pbxsecretIDi (2 words)                    |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                  pvr (length depends on KA Type)              |
   |                               . . .                           |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         MAC (2 words)                         |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~~~~~~~~
{: #FigKEMPart1Message title="KEMPart1 Message Format"}

## KEMPart2 Message

~~~~~~~~~~

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0 1 0 1 0 0 0 0 0 1 0 1 1 0 1 0|        length=25 words        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |              Message Type Block="KEMPart2" (2 words)          |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                   Hash image H1 (8 words)                     |
   |                             . . .                             |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        rs1IDi (2 words)                       |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        rs2IDi (2 words)                       |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     auxsecretIDi (2 words)                    |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     pbxsecretIDi (2 words)                    |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                          ni (4 words)                         |
   |                               . . .                           |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         MAC (2 words)                         |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~~~~~~~~
{: #FigKEMPart2Message title="KEMPart2 Message Format"}

## Confirm1 and Confirm2 Message

## Conf2ACK Message

## Error Message

## ErrorACK Message

## GoClear Message

## ClearACK Message

## SASRelay Message

## RelayACK Message

## Ping Message

## PingACK Message

# Hybrid KEM {#HybridKEMSec}

PQC KEM algorithm being quite recent, it is recommended to combine them with well-known, classical key exchange algorithms to obtain an hybrid KEM. We defined a method to hybridize key exchange schemes by providing an interface identical to a "simple" KEM:

* Generate a fresh set of key pair:

~~~
publicKey, secretKey = KEMgenKey()
~~~

* Generate a sharedSecret and encapsulates it in cipherText using the given publicKey:

~~~
sharedSecret, cipherText = KEMencaps( publicKey )
~~~

* Use the given secretKey to compute the sharedSecret encapsulated in cipherText:

~~~
sharedSecret = KEMdecaps( cipherText, secretKey )
~~~


This makes the handling of Hybrid KEM by ZRTP transparent and will allow the switch to PQC KEM only once the confidence in this kind algorithm reaches an acceptable level.

We first define an ECDH-KEM based and then a way to combine two KEM algorithms.

## ECDH-based KEM {#ECHDBasedKEMSec}

Based on Section 4.1 of {{RFC9180}}, we define a scheme to provide a KEM interface based on ECDH algorithms.

ECDH interface is the following:

* Generate a fresh set of key pair:

~~~
publicKey, secretKey = ECDHgenKey()
~~~

* Compute the shared secret given self secret key and peer public key

~~~
sharedSecret = ECDHcomputeShared( selfSecret, peerPublic )
~~~

* Derive the public key given the secret one

~~~
publicKey = ECDHderivePublicKey( secretKey )
~~~

The ECDH-based KEM relies upon HKDF as defined in {{RFC5869}} based on the negotiated hash algorithm:

~~~
kfd ( ikm, context, outputSize ):
   ikm = "ZRTP" || ECDHId || "aea_prk" || ikm
   salt = ""
   info =  outputSize || "ZRTP" || ECDHId
              || "shared_secret" || context
   return HKDF( ikm, salt, info, outputSize )

KEMgenKey():
   return ECDHgenKey()

KEMencaps( publicKey ):
   skE, pkE = ECDHgenKey()
   ss = ECDHcomputeShared( skE, publicKey )
   return kdf( ss, pkE || publicKey, sizeof(ss) ), pkE

KEMdecaps( cipherText, secretKey ):
   ss = ECDHcomputeShared( secretKey, cipherText )
   publicKey = ECDHderivePublicKey( secretKey )
   return kdf( ss, cipherText || publicKey, sizeof(ss) )
~~~

The implicit value ECDHId defined as follow:

| ECDHId | base ECDH | Reference |
|:-------|:----------|:----------|
| 0x0020 | X25519    | {{RFC7748}} |
| 0x0021 | X448      | {{RFC7748}} |
| 0x0022 | X41417    | {{Ber14}} |
{: #ecdhid-values title="ECDH IDs"}

## KEM Combiner {#KEMcombiner}

Section 3.3 in {{Bin18}} describes a way of combining several KEMs into one. We apply this to build an hybrid KEM from two or more KEMs using HMAC-SHA as dual Pseudo Random Function and extractor.


PublicKey, secretKey and cipherText sizes are implicitly known for each component KEM, so the function "split" can separate the concatenated entities. The following pseudo code combines n KEMs together, each component is noted KEM\[i\].

* Generate a fresh set of key pair:

~~~
publicKey, secretKey = KEMgenKey():
   for i in [1..n]
       pk[i], sk[i] = KEM[i].genKey()

   return pk[1] || .. || pk[n], sk[1] || .. || sk[n]
~~~

* Generate a sharedSecret and encapsulate it in cipherText using the given publicKey:

~~~
sharedSecret, cipherText = KEMencaps( publicKey ):
   pk[1], .. , pk[n] = split( publicKey )

   for i in [1..n]
      ss[i], ct[i] = KEM[i].encaps( pk[i] )

   cipherText = ct[1] || .. || ct[n]

   k[1] = HMAC( "", ss[1] )
   for in in [2..n]
       k[i] = HMAC( k[i-1], ss[i] )

   sharedSecret = HMAC( k[n], cipherText)

   return sharedSecret, cipherText
~~~

* Use the given secretKey to compute the sharedSecret encapsulated in cipherText:

~~~
sharedSecret = KEMdecaps( cipherText, secretKey ):
   sk[1], .. , sk[n] = split( secretKey )
   ct[1], .. , ct[n] = split( cipherText )

   for i in [1..n]
       ss[i] = KEM[i].decaps( ct[i], sk[i] )

   k[1] = HMAC( "", ss1 )
   for in in [2..n]
       k[i] = HMAC( k[i-1], ss[i] )

   sharedSecret = HMAC( k[n], cipherText )

   return sharedSecret
~~~

The HMAC function is based on the negotiated hash algorithm.

# Retransmissions

# Short Authentication String {#SASSec}

## SAS Verified Flag

## Signing the SAS {#signingSASsec}

In most applications, it is desirable to avoid the added complexity of a PKI-backed digital signature, which is why ZRTP is designed not to require it. Nonetheless, in some applications, it may be hard to arrange for two human users to verbally compare the SAS. Or, an application may already be using an existing PKI and wants to use it to augment ZRTP.

To handle these cases, ZRTP allows for an OPTIONAL signature feature, which allows the SAS to be checked without human participation. The SAS MAY be signed and the signature sent inside the Confirm1, Confirm2 (Figure 10), or SASrelay (Figure 16) messages. The signature type (Section {{SignatureTypeBlockSec}}), length of the signature, and the key used to create the signature (or a link to it) are all sent along with the signature. The signature is calculated across the entire SAS hash result (sashash), from which the sasvalue was derived. The signatures exchanged in the encrypted Confirm1, Confirm2, or SASrelay messages MAY be used to authenticate the ZRTP exchange. A signature may be sent only in the initial media stream in a DH or ECDH ZRTP exchange, not in Multistream mode.

The initiator computes its signature as follows:

~~~
sigi = sign(Initiator's private key, "Initiator" || Initiator's public key || sashash)
~~~

The responder computes its signature as follows:

~~~
sigr = sign(Responder's private key, "Responder" || Responder's public key || sashash)
~~~

Although the signature is sent, the material that is signed, the sashash, is not sent with it in the Confirm message, since both parties have already independently calculated the sashash. That is not the case for the SASrelay message, which must relay the sashash. To avoid unnecessary signature calculations, a signature SHOULD NOT be sent if the other ZRTP endpoint did not set the (S) flag in the Hello message (Section {{HelloMessageSec}}).

Note that the choice of hash algorithm used in the digital signature is independent of the hash used in the sashash. The sashash is determined by the negotiated Hash Type (Section {{HashTypeBlockSec}}), while the hash used by the digital signature is separately defined by the digital signature algorithm. For example, the sashash may be based on SHA-256, while the digital signature might use SHA-384, if an ECDSA P-384 key is used.

If the sashash (which is always truncated to 256 bits) is shorter than the signature hash, the security is not weakened because the hash commitment precludes the attacker from searching for sashash collisions.

ECDSA algorithms may be used with either OpenPGP-formatted keys, or X.509v3 certificates. If the ZRTP key exchange is ECDH, and the SAS is signed, then the signature SHOULD be ECDSA, and SHOULD use the same size curve as the ECDH exchange if an ECDSA key of that size is available.

If a ZRTP endpoint supports incoming signatures (evidenced by setting the (S) flag in the Hello message), it SHOULD be able to parse signatures from the other endpoint in OpenPGP format and MUST be able to parse them in X.509v3 format. If the incoming signature is in an unsupported format, or the trust model does not lead to a trusted introducer or a trusted certificate authority (CA), another authentication method may be used if available, such as the SAS compare, or a cached shared secret from a previous session. If none of these methods are available, it is up to the ZRTP user agent and the user to decide whether to proceed with the call, after the user is informed.

ECDSA {{NIST-FIPS186-5}} has a feature that allows most of the signature calculation to be done in advance of the session, reducing latency during call setup. This is useful for low-power mobile handsets.

ECDSA is preferred because it has compact keys as well as compact signatures. However, if the signature along with its public key certificate are insufficiently compact, the Confirm message may become too long for the maximum transmission unit (MTU) size, and fragmentation is applied to ZRTP messages (see Section {{ZRTPPacketFormatsSec}}). This avoids using UDP fragmentation. Indeed, if UDP fragmentation is applied, then some firewalls and NATs may discard fragmented UDP packets, which would cause the ZRTP exchange to fail. Such an issue is now mitigated thanks to ZRTP messages fragmentation.

From a packet-size perspective, ECDSA produces equally compact signatures for a given signature strength.

All signatures generated MUST use only NIST-approved hash algorithms, and MUST avoid using SHA1. This applies to both OpenPGP and X.509v3 signatures. NIST-approved hash algorithms are found in {{NIST-FIPS186-5}}. All ECDSA curves used throughout this spec are over prime fields, drawn from Section 4.2 of {{NIST-SP800-186}}.

## Relaying SAS through a PBX


# Signaling Interactions

## Binding the Media Stream to the Signaling Layer via the Hello Hash {#zrtphashsec}

### Integrity-Protected Signaling Enables Integrity-Protected DH Exchange {#integritysignalingsec}

# False ZRTP Packet Rejection

# Intermediary ZRTP Devices

# ZRTP Disclosure Flag

# Mapping between ZID and AOR (SIP URI)

# IANA Considerations

# Media Security Requirements

# Security Considerations

## Self-Healing Key Continuity Feature {#SelfHealingKeyContinuityFeatureSec}

# Acknowledgements

--- back

# Change history

version 00.

--- fluff
