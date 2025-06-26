import Foundation
import CryptoKit

protocol HashAlgorithm {
	associatedtype Hasher: DataHasher
	func hasher() -> Hasher
}

struct SHA256Digest: HashAlgorithm {
	func hasher() -> SHA256Hasher {
		SHA256Hasher()
	}
}
