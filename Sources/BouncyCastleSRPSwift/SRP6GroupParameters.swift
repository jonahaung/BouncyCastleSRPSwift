//
//  SRP6GroupParameters.swift
//  BouncyCastleSRPSwift
//
//  Created by Aung Ko Min on 26/6/25.
//

import Foundation
import BigInt

public struct SRP6GroupParameters {
	public let N: BigInt
	public let G: BigInt

	public init(N: BigInt, G: BigInt) {
		self.N = N
		self.G = G
	}
}

/*
 let params = SRP6GroupParameters(N: someBigIntN, G: someBigIntG)
 */
