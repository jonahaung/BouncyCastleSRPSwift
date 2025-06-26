import Foundation
import CryptoKit

struct SRPPayloadEncryptor {
    private let srpSharedSecret: Data
    
    init(srpSharedSecret: Data) {
        self.srpSharedSecret = srpSharedSecret
    }
    
    // Step 1: Serialize payload
    private func serializePayload(_ card: CardPayload) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys // Ensure consistent ordering
        return try encoder.encode(card)
    }
    
    // Step 2: Derive AES key from SRP shared secret
    private func deriveAESKey() throws -> SymmetricKey {
        // Use HKDF to derive a key suitable for AES
        let hashFunction = SHA256.self
        let derivedKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: .init(data: srpSharedSecret),
            outputByteCount: 32 // 256-bit key for AES
        )
        return derivedKey
    }
    
    // Steps 3-5: Encrypt and encode
    func encryptPayload(_ card: CardPayload) throws -> (encryptedData: String, iv: String) {
        // 1. Serialize
        let payloadData = try serializePayload(card)
        
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
    
    // Step 6: Prepare final request
    func createRequest(
        card: CardPayload,
        setupSessionId: String,
        stripeSourceId: String,
        clientId: String,
        customerId: String,
        deviceId: String
    ) throws -> SRPPayloadRequest {
        let (encryptedData, iv) = try encryptPayload(card)
        
        return SRPPayloadRequest(
            srp: .init(
                securePayload: encryptedData,
                iv: iv,
                setupSessionId: setupSessionId
            ),
            stripeSourceId: stripeSourceId,
            clientId: clientId,
            customerId: customerId,
            deviceId: deviceId
        )
    }
    
    enum EncryptionError: Error {
        case encryptionFailed
        case invalidInput
    }
}
