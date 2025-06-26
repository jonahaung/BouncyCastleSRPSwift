//
//  DataHasher.swift
//  BouncyCastleSRPSwift
//
//  Created by Aung Ko Min on 26/6/25.
//

import Foundation
import CryptoKit

public protocol DataHasher {
	mutating func update(data: Data)
	func finalize() -> Data
}

public struct SHA256Hasher: DataHasher {
	private var hasher: SHA256

	public init() {
		self.hasher = SHA256()
	}

	public mutating func update(data: Data) {
		hasher.update(data: data)
	}

	public func finalize() -> Data {
		Data(hasher.finalize())
	}
}

/*
 var hasher = SHA256Hasher()
 hasher.update(data: Data("hello".utf8))
 let digest = hasher.finalize()
 */
