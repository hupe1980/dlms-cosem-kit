+++
title = "Protocol support"
description = "Supported services, security mechanisms, transport limits and verification coverage."
weight = 80
+++

## Protocol support

| Area | Supported |
|---|---|
| Associations | Logical-name referencing, optional short-name referencing, LLS and HLS-GMAC |
| Services | GET, SET, ACTION, ACCESS, selective access, service blocks, general block transfer and push notifications |
| Profiles | Capture-object descriptors, clock and entry selectors, null repetition, shortened rows and delta expansion |
| Blocking client | Owned reads, reads into caller storage, list reads, scaled registers and method calls |
| Security | Symmetric AES-GCM for suites 0–2, global and dedicated keys, key wrap and replay protection |
| Transports | HDLC, TCP/UDP wrapper framing, blocking TCP and HDLC drivers, DSMR and eMUCs P1 telegrams |

## Compatibility limits

- HLS-GMAC is the supported high-level authentication mechanism. Asymmetric key agreement,
  signing and certificate processing for suites 1 and 2 are outside the supported set.
- General ciphering supports the identified-key form on receive. Wrapped and agreed key
  information, general signing and V.44 compression return an error.
- Short-name reads support block transfer. Short-name writes and batched ACTION parameters
  must fit the supported request forms. Specify each class's short-name method offset.
- The host supplies transport deadlines, HDLC retransmission timing and push scheduling.

## Verification

The suite checks published Initiate encodings, NIST cipher vectors, RFC 3394 key-wrap
vectors and CRC check values. Integration tests run both engines over in-memory and
socket transports. CI also fuzzes decoders, builds embedded targets and checks Cortex-M
release objects for panic symbols.

Independent meter interoperability has not been verified. In particular, confirm GBT
window acknowledgements and HDLC segmentation against your peer. ACCESS result lists
are matched by position, unsigned deltas are increments, and short-name
`InformationReport` timestamps are returned as received octets.
