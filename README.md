# ContinuoSecurityTransport

ContinuoSecurityTransport is the security source available for audit from
Continuo, a commercial proprietary macOS application. This package is not OSI-approved open source and is not the complete Continuo product.

The Continuo product currently consumes the pairing, identity-pinning,
privacy-safe discovery, bounded security-handshake framing, and secure inbound
connection-admission code in this package. The package also contains a staged generic session-crypto implementation with pure tests; it is not the shipped input-encryption implementation yet.

## Build and test

The package requires macOS 14 or later and Swift 6.

```sh
swift build
swift test
```

The standalone package has no third-party Swift package dependencies. It uses
Apple system frameworks provided by macOS. See [THIRD_PARTY.md](THIRD_PARTY.md)
for the package boundary.

## Mirror status and authority

This directory supplies fixed inputs for a generated downstream security
mirror. A mirror snapshot is for inspection and testing; it is not the
authoritative development repository. The corresponding source and release
records maintained in Continuo's private development repository remain
authoritative. Generated-mirror changes must be made upstream and regenerated
rather than treated as product-source changes.

This snapshot is published for security evaluation under the Continuo Security
Evaluation License. It grants inspection, building, and testing rights only —
not production use, redistribution, or trademark use. Review [LICENSE](LICENSE)
before using the package.

## Scope

This package is limited to the security transport source and its tests.
Proprietary application code remains outside the package, including product UI,
application orchestration, input capture and injection, file-transfer product
flows, licensing, updating, distribution, and other release-app integrations.
The source in this package therefore cannot by itself represent or build the
complete Continuo application.

For network-boundary details, see [NETWORK.md](NETWORK.md). The security
assumptions and exclusions are documented in
[THREAT_MODEL.md](THREAT_MODEL.md).

## Vulnerability reports

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
Do not disclose an uncoordinated vulnerability in a public issue.
Contributions and pull requests are not solicited.
This downstream snapshot is generated from Continuo's private authoritative
repository.
