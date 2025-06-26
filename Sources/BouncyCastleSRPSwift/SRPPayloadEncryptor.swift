//
//  SRPPayloadEncryptor.swift
//  BouncyCastleSRPSwift
//
//  Created by Aung Ko Min on 26/6/25.
//

import Foundation
import CryptoKit

public struct SRPPayloadEncryptor {
	private let srpSharedSecret: Data

	public init(srpSharedSecret: Data) {
		self.srpSharedSecret = srpSharedSecret
	}

	// Step 1: Serialize payload
	private func serializePayload(_ model: any Codable) throws -> Data {
		let encoder = JSONEncoder()
		encoder.outputFormatting = .sortedKeys // Ensure consistent ordering
		return try encoder.encode(model)
	}

	// Step 2: Derive AES key from SRP shared secret
	private func deriveAESKey() throws -> SymmetricKey {
		// Use HKDF to derive a key suitable for AES
		return HKDF<SHA256>.deriveKey(
			inputKeyMaterial: .init(data: srpSharedSecret),
			outputByteCount: 32 // 256-bit key for AES
		)
	}

	// Steps 3-5: Encrypt and encode
	public func encryptPayload(_ model: any Codable) throws -> (encryptedData: String, iv: String) {
		// 1. Serialize
		let payloadData = try serializePayload(model)

		// 2. Derive key
		let aesKey = try deriveAESKey()

		// 3. Generate IV (nonce)
		let iv = AES.GCM.Nonce()

		// 4. Encrypt using AES-GCM
		let sealedBox = try AES.GCM.seal(payloadData, using: aesKey, nonce: iv)

		guard let combinedData = sealedBox.combined else {
			throw EncryptionError.encryptionFailed
		}

		// 5. Base64 encode
		return (
			encryptedData: combinedData.base64EncodedString(),
			iv: Data(iv).base64EncodedString()
		)
	}

	public enum EncryptionError: Error {
		case encryptionFailed
		case invalidInput
	}
}
