//
//  SRP6Client.swift
//  BouncyCastleSRPSwift
//
//  Created by Aung Ko Min on 26/6/25.
//

import Foundation
import CryptoKit
import BigInt

public final class SRP6Client {

	// MARK: - Constants
	public let N: BigInt
	public let g: BigInt
	public let digest: SHA256Digest
	public let random: SecureRandom

	// MARK: - Client Private Values
	public let a: BigInt
	public let x: BigInt

	// MARK: - Public Values
	public private(set) var A: BigInt

	// MARK: - Server Values
	private var B: BigInt?
	private var u: BigInt?

	// MARK: - Session Values
	private var S: BigInt?
	private var M1: BigInt?
	private var M2: BigInt?
	private var sessionKey: BigInt?

	// MARK: - Initialization

	public init(
		N: BigInt,
		g: BigInt,
		digest: SHA256Digest,
		random: SecureRandom,
		salt: Data,
		identity: String,
		password: String
	) {
		self.N = N
		self.g = g
		self.digest = digest
		self.random = random

		self.x = SRP6Util.calculateX(
			digest: digest,
			N: N,
			salt: salt,
			identity: Data(identity.utf8),
			password: Data(password.utf8)
		)
		self.a = SRP6Util.generatePrivateValue(digest: digest, N: N, g: g, random: random)
		self.A = g.power(a, modulus: N)
	}

	public convenience init(
		group: SRP6GroupParameters,
		digest: SHA256Digest,
		random: SecureRandom,
		salt: Data,
		identity: String,
		password: String
	) {
		self.init(
			N: group.N,
			g: group.G,
			digest: digest,
			random: random,
			salt: salt,
			identity: identity,
			password: password
		)
	}

	// MARK: - Authentication Flow

	public func startAuthentication() -> BigInt {
		return A
	}

	public func calculateSecret(serverB: BigInt) throws -> BigInt {
		let B = try SRP6Util.validatePublicValue(N: N, val: serverB)
		let u = SRP6Util.calculateU(digest: digest, N: N, A: A, B: B)
		let S = calculateS(B: B, u: u)

		self.B = B
		self.u = u
		self.S = S

		return S
	}

	private func calculateS(B: BigInt, u: BigInt) -> BigInt {
		let k = SRP6Util.calculateK(digest: digest, N: N, g: g)
		let exp = u * x + a
		let tmp = (g.power(x, modulus: N) * k) % N
		return (B - tmp).modulus(N).power(exp, modulus: N)
	}

	// MARK: - Evidence Messages

	public func calculateClientEvidenceMessage() throws -> BigInt {
		guard let B = B, let S = S else {
			throw CryptoError.missingData("Cannot compute M1: missing required values (B, S)")
		}

		let M1 = SRP6Util.calculateM1(digest: digest, N: N, A: A, B: B, S: S)
		self.M1 = M1
		return M1
	}

	public func verifyServerEvidenceMessage(serverM2: BigInt) throws -> Bool {
		guard let M1 = M1, let S = S else {
			throw CryptoError.missingData("Cannot verify M2: missing required values (M1, S)")
		}

		let computedM2 = SRP6Util.calculateM2(
			digest: digest,
			N: N,
			A: A,
			M1: M1,
			S: S
		)

		guard computedM2 == serverM2 else {
			return false
		}

		self.M2 = serverM2
		return true
	}

	// MARK: - Session Key

	public func calculateSessionKey() throws -> BigInt {
		guard let S = S, M1 != nil, M2 != nil else {
			throw CryptoError.missingData("Cannot compute session key: missing required values (S, M1, M2)")
		}

		let key = SRP6Util.calculateKey(digest: digest, N: N, S: S)
		self.sessionKey = key
		return key
	}

	public func getSessionKey() throws -> BigInt {
		guard let key = sessionKey else {
			throw CryptoError.missingData("Session key not yet calculated")
		}
		return key
	}
}
