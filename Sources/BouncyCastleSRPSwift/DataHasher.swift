import Foundation
import CryptoKit

protocol DataHasher {
	mutating func update(data: Data)
	func finalize() -> Data
}

struct SHA256Hasher: DataHasher {
	private var hasher: SHA256
	init() {
		self.hasher = SHA256()
	}
	mutating func update(data: Data) {
		hasher.update(data: data)
	}
	func finalize() -> Data {
		Data(hasher.finalize())
	}
}