//
//  SecureRandom.swift
//  BouncyCastleSRPSwift
//
//  Created by Aung Ko Min on 26/6/25.
//

import Foundation
import Security

public protocol SecureRandom {
	func generateBytes(count: Int) -> Data
}

public struct SystemRandom: SecureRandom {
	public init() {} // Needed to initialize from other modules

	public func generateBytes(count: Int) -> Data {
		var bytes = [UInt8](repeating: 0, count: count)
		_ = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
		return Data(bytes)
	}
}
