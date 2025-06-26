//
//  SRP6Util.swift
//  BouncyCastleSRPSwift
//
//  Created by Aung Ko Min on 26/6/25.
//


import Foundation
import CryptoKit
import BigInt

struct SRP6Util {

	// MARK: - Constants
	private static let zero = BigInt(0)
	private static let one = BigInt(1)

	// MARK: - Public Functions

	static func calculateK<H: HashAlgorithm>(digest: H, N: BigInt, g: BigInt) -> BigInt {
		hashPaddedPair(digest: digest, N: N, values: [N, g])
	}

	static func calculateU<H: HashAlgorithm>(digest: H, N: BigInt, A: BigInt, B: BigInt) -> BigInt {
		hashPaddedPair(digest: digest, N: N, values: [A, B])
	}

	static func calculateX<H: HashAlgorithm>(
		digest: H,
		N: BigInt,
		salt: Data,
		identity: Data,
		password: Data
	) -> BigInt {
		let hash1 = hashIdentityPassword(digest: digest, identity: identity, password: password)
		return hashSaltIdentityPassword(digest: digest, salt: salt, hash1: hash1)
	}

	static func generatePrivateValue<H: HashAlgorithm>(
		digest: H,
		N: BigInt,
		g: BigInt,
		random: SecureRandom
	) -> BigInt {
		let minBits = min(256, N.bitWidth / 2)
		let min = one << (minBits - 1)
		let max = N - one

		return generateRandomInRange(random: random, min: min, max: max)
	}

	static func validatePublicValue(N: BigInt, val: BigInt) throws -> BigInt {
		let val = val % N

		guard val != zero else {
			throw SRP6UtilError.invalidPublicValue
		}

		return val
	}

	static func calculateM1<H: HashAlgorithm>(
		digest: H,
		N: BigInt,
		A: BigInt,
		B: BigInt,
		S: BigInt
	) -> BigInt {
		hashPaddedTriplet(digest: digest, N: N, values: [A, B, S])
	}

	static func calculateM2<H: HashAlgorithm>(
		digest: H,
		N: BigInt,
		A: BigInt,
		M1: BigInt,
		S: BigInt
	) -> BigInt {
		hashPaddedTriplet(digest: digest, N: N, values: [A, M1, S])
	}

	static func calculateKey<H: HashAlgorithm>(digest: H, N: BigInt, S: BigInt) -> BigInt {
		let paddedS = padNumber(S, toLength: (N.bitWidth + 7) / 8)
		return hashData(digest: digest, data: paddedS)
	}

	// MARK: - Private Helper Functions

	private static func hashIdentityPassword<H: HashAlgorithm>(
		digest: H,
		identity: Data,
		password: Data
	) -> Data {
		var hasher = digest.hasher()
		hasher.update(data: identity)
		hasher.update(data: Data(":".utf8))
		hasher.update(data: password)
		return hasher.finalize()
	}

	private static func hashSaltIdentityPassword<H: HashAlgorithm>(
		digest: H,
		salt: Data,
		hash1: Data
	) -> BigInt {
		var hasher = digest.hasher()
		hasher.update(data: salt)
		hasher.update(data: hash1)
		return BigInt(data: hasher.finalize())
	}

	private static func generateRandomInRange(
		random: SecureRandom,
		min: BigInt,
		max: BigInt
	) -> BigInt {
		let range = max - min
		let bits = range.bitWidth

		while true {
			let randomData = random.generateBytes(count: (bits + 7) / 8)
			let randomNum = BigInt(data: randomData) % range + min

			if randomNum >= min && randomNum <= max {
				return randomNum
			}
		}
	}

	private static func hashPaddedPair<H: HashAlgorithm>(
		digest: H,
		N: BigInt,
		values: [BigInt]
	) -> BigInt {
		precondition(values.count == 2, "Pair hash requires exactly 2 values")
		return hashPaddedValues(digest: digest, N: N, values: values)
	}

	private static func hashPaddedTriplet<H: HashAlgorithm>(
		digest: H,
		N: BigInt,
		values: [BigInt]
	) -> BigInt {
		precondition(values.count == 3, "Triplet hash requires exactly 3 values")
		return hashPaddedValues(digest: digest, N: N, values: values)
	}

	private static func hashPaddedValues<H: HashAlgorithm>(
		digest: H,
		N: BigInt,
		values: [BigInt]
	) -> BigInt {
		let padLength = (N.bitWidth + 7) / 8
		var hasher = digest.hasher()

		for value in values {
			let padded = padNumber(value, toLength: padLength)
			hasher.update(data: padded)
		}

		return BigInt(data: hasher.finalize())
	}

	private static func hashData<H: HashAlgorithm>(digest: H, data: Data) -> BigInt {
		var hasher = digest.hasher()
		hasher.update(data: data)
		return BigInt(data: hasher.finalize())
	}

	private static func padNumber(_ n: BigInt, toLength length: Int) -> Data {
		let bytes = n.serialize()

		if bytes.count < length {
			var padded = Data(count: length - bytes.count)
			padded.append(bytes)
			return padded
		}

		return bytes
	}
}
