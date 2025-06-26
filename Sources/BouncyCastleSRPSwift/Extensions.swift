//
//  Extensions.swift
//  BouncyCastleSRPSwift
//
//  Created by Aung Ko Min on 26/6/25.
//

import BigInt
import Foundation

// MARK: - BigInt Extensions

public extension BigInt {
	/// Initializes BigInt from `Data`
	init(data: Data) {
		self.init(sign: .plus, magnitude: BigUInt(data))
	}

	/// Serializes BigInt to `Data`
	func serialize() -> Data {
		magnitude.serialize()
	}

	/// Bit width of the BigInt (backed by BigUInt)
	var bitWidth: Int {
		magnitude.bitWidth
	}
}

/*
 let bigInt = BigInt(data: someData)
 let serialized = bigInt.serialize()
 */
