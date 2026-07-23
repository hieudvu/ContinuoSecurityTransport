# Threat Model

## Security objectives

The package is intended to support authenticated local-peer establishment,
identity pinning, privacy-safe discovery, bounded security-handshake framing,
and admission of inbound connections only after the applicable security checks.
The staged generic session-crypto implementation is evaluated as package code;
it is not a claim about the shipped input-encryption path.

## Adversaries and covered threats

- **Hostile LAN peers:** An untrusted device on the local network may discover,
  contact, race, replay, or impersonate a peer and may send arbitrary bytes.
- **Passive sniffing:** An observer may capture local-network discovery,
  handshake, and peer-connection traffic.
- **Active man-in-the-middle attacks:** An attacker may intercept, inject,
  reorder, suppress, or modify traffic during discovery or connection setup.
- **Identity replacement:** An attacker may attempt to substitute a different
  peer identity or cause a previously pinned identity to be replaced without
  the intended trust decision.
- **Malformed frames:** A peer may send truncated, oversized, inconsistent, or
  otherwise malformed handshake frames to trigger parser, resource-use, or
  state-machine failures.

Review should verify that authentication and identity-pinning decisions resist
these threats, that framing is bounded before allocation or processing, and
that failed admission does not create a trusted peer.

## Trust assumptions

Trusted endpoints are devices whose operators completed the intended pairing
and trust decision and whose pinned identity remains available and uncompromised.
The model assumes the operating system, cryptographic primitives supplied by
system frameworks, and the trusted endpoint's local execution environment
behave as documented.

## Exclusions

- **Compromised hosts:** Malware, administrator-level compromise, stolen local
  credentials, or extraction of key material from an already compromised
  trusted endpoint is outside this package threat model.
- **Traffic analysis:** Hiding packet timing, connection presence, endpoint
  addresses, or traffic volume from a network observer is not an objective.
- **Proprietary product surfaces:** Application UI, input capture and injection,
  file-transfer product flows, licensing, updating, distribution, and other
  release-app integrations are outside this package. They require separate
  product-level review.

These exclusions limit the claims made for this source package; they do not
assert that excluded risks are absent from the complete product.
