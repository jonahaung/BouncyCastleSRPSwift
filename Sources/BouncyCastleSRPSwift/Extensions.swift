import BigInt
import Foundation

// MARK: - BigInt Extensions

extension BigInt {
	init(data: Data) {
		self.init(sign: .plus, magnitude: BigUInt(data))
	}

	func serialize() -> Data {
		magnitude.serialize()
	}

	var bitWidth: Int {
		magnitude.bitWidth
	}
}
