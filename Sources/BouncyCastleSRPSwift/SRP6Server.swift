//
//  SRP6Server.swift
//  BouncyCastleSRPSwift
//
//  Created by Aung Ko Min on 26/6/25.
//

import Foundation
import CryptoKit
import BigInt

public final class SRP6Server {
	// MARK: - Constants
	private let N: BigInt
	private let g: BigInt

	// MARK: - State Variables
	private let v: BigInt
	private let random: SecureRandom
	private let digest: SHA256Digest

	// MARK: - Protocol State
	private var A: BigInt?
	private var b: BigInt?
	private var B: BigInt?
	private var u: BigInt?
	private var S: BigInt?
	private var M1: BigInt?
	private var M2: BigInt?
	private var sessionKey: BigInt?

	// MARK: - Initialization

	public init(N: BigInt, g: BigInt, v: BigInt, digest: SHA256Digest, random: SecureRandom) {
		self.N = N
		self.g = g
		self.v = v
		self.random = random
		self.digest = digest
	}

	public convenience init(group: SRP6GroupParameters, v: BigInt, digest: SHA256Digest, random: SecureRandom) {
		self.init(N: group.N, g: group.G, v: v, digest: digest, random: random)
	}

	// MARK: - Public Methods

	/// Generates server credentials (public value B)
	public func generateServerCredentials() throws -> BigInt {
		let k = SRP6Util.calculateK(digest: digest, N: N, g: g)
		self.b = try generatePrivateValue()

		let term1 = (k * v) % N
		let term2 = g.power(b!, modulus: N)
		self.B = (term1 + term2) % N

		guard let B = self.B else {
			throw CryptoError.calculationError("Failed to generate server credentials")
		}

		return B
	}

	/// Calculates the shared secret using client's public value A
	public func calculateSharedSecret(clientA: BigInt) throws -> BigInt {
		self.A = try SRP6Util.validatePublicValue(N: N, val: clientA)
		self.u = SRP6Util.calculateU(digest: digest, N: N, A: A!, B: B!)
		self.S = try calculateSValue()

		guard let S = self.S else {
			throw CryptoError.calculationError("Failed to calculate shared secret")
		}

		return S
	}

	/// Verifies client's evidence message M1
	public func verifyClientEvidenceMessage(clientM1: BigInt) throws -> Bool {
		guard let A = self.A, let B = self.B, let S = self.S else {
			throw CryptoError.missingData("Cannot verify M1: missing required values (A, B, or S)")
		}

		let computedM1 = SRP6Util.calculateM1(digest: digest, N: N, A: A, B: B, S: S)

		if computedM1 == clientM1 {
			self.M1 = clientM1
			return true
		}
		return false
	}

	/// Calculates server's evidence message M2
	public func calculateServerEvidenceMessage() throws -> BigInt {
		guard let A = self.A, let M1 = self.M1, let S = self.S else {
			throw CryptoError.missingData("Cannot calculate M2: missing required values (A, M1, or S)")
		}

		self.M2 = SRP6Util.calculateM2(digest: digest, N: N, A: A, M1: M1, S: S)

		guard let M2 = self.M2 else {
			throw CryptoError.calculationError("Failed to calculate server evidence message")
		}

		return M2
	}

	/// Calculates the session key
	public func calculateSessionKey() throws -> BigInt {
		guard let S = self.S else {
			throw CryptoError.missingData("Cannot calculate session key: missing shared secret (S)")
		}

		self.sessionKey = SRP6Util.calculateKey(digest: digest, N: N, S: S)

		guard let sessionKey = self.sessionKey else {
			throw CryptoError.calculationError("Failed to calculate session key")
		}

		return sessionKey
	}

	// MARK: - Private Methods

	private func generatePrivateValue() throws -> BigInt {
		return SRP6Util.generatePrivateValue(digest: digest, N: N, g: g, random: random)
	}

	private func calculateSValue() throws -> BigInt {
		guard let u = self.u, let A = self.A, let b = self.b else {
			throw CryptoError.missingData("Cannot calculate S: missing required values (u, A, or b)")
		}

		let term1 = v.power(u, modulus: N)
		let term2 = (term1 * A) % N
		return term2.power(b, modulus: N)
	}
}

// MARK: - Error Handling

public extension SRP6Server {
	enum CryptoError: Error {
		case missingData(String)
		case calculationError(String)
	}
}

/*
 let server = SRP6Server(group: groupParams, v: verifier, digest: SHA256Digest(), random: SystemRandom())
 let B = try server.generateServerCredentials()
 // etc...
 */
