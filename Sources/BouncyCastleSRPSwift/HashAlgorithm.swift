//
//  HashAlgorithm.swift
//  BouncyCastleSRPSwift
//
//  Created by Aung Ko Min on 26/6/25.
//

import Foundation
import CryptoKit

public protocol HashAlgorithm {
	associatedtype Hasher: DataHasher
	func hasher() -> Hasher
}

public struct SHA256Digest: HashAlgorithm {
	public init() {}

	public func hasher() -> SHA256Hasher {
		SHA256Hasher()
	}
}
