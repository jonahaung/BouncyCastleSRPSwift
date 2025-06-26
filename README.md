BouncyCastleSRPSwift

A lightweight, modular Swift implementation of the Secure Remote Password protocol (SRP-6a), inspired by Bouncy Castle.

This library allows secure mutual authentication and shared key establishment without exposing passwords, ideal for client-server communication over insecure channels.

⸻

Features
	•	🔐 Pure Swift SRP-6a implementation (Client and Server)
	•	🔐 AES-GCM payload encryption using the SRP-derived session key
	•	📦 Codable support for easy payload serialization
	•	📐 Multiple RFC 5054-compliant standard group parameters
	•	🧩 Modular and extensible architecture

⸻

Installation

Use Swift Package Manager. Add the following to your Package.swift:

.package(url: "https://github.com/yourusername/BouncyCastleSRPSwift.git", from: "1.0.0")

Then import where needed:

import BouncyCastleSRPSwift


⸻

Components

SRP6Client

Client-side SRP logic:

let client = SRP6Client(
    group: SRP6StandardGroups.RFC5054_2048,
    digest: SHA256Digest(),
    random: SecureRandom(),
    salt: salt,
    identity: "username",
    password: "password"
)

let A = client.startAuthentication()
// Send A to server, receive B
let S = try client.calculateSecret(serverB: B)
let M1 = try client.calculateClientEvidenceMessage()
// Send M1, receive M2
let valid = try client.verifyServerEvidenceMessage(serverM2: M2)
let sessionKey = try client.calculateSessionKey()

SRP6Server

Server-side SRP logic:

let server = SRP6Server(
    N: group.N,
    g: group.G,
    v: verifier,
    digest: SHA256Digest(),
    random: SecureRandom()
)

let B = try server.generateServerCredentials()
let S = try server.calculateSecret(clientA: A)
let valid = try server.verifyClientEvidenceMessage(clientM1: M1)
let M2 = try server.calculateServerEvidenceMessage()
let sessionKey = try server.calculateSessionKey()

SRP6StandardGroups

RFC 5054-compliant Diffie-Hellman group parameters:

let group = SRP6StandardGroups.RFC5054_2048

Groups supported: 1024, 1536, 2048, 3072, 4096, 6144, 8192 bits

SRPPayloadEncryptor

Encrypts any Codable payload using AES-GCM:

let encryptor = SRPPayloadEncryptor(srpSharedSecret: sessionKeyData)
let (encryptedData, iv) = try encryptor.encryptPayload(myCodableModel)


⸻

Requirements
	•	Swift 5.8+
	•	iOS 13+ / macOS 10.15+

⸻

License

MIT License

⸻

Acknowledgments
	•	Bouncy Castle
	•	RFC 5054

⸻

TODO
	•	DecryptPayload method
	•	SRP Verifier utility generator
	•	Add Unit Tests and CI
