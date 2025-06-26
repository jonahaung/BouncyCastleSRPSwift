//
//  SRP6UtilError.swift
//  BouncyCastleSRPSwift
//
//  Created by Aung Ko Min on 26/6/25.
//

import Foundation
import CryptoKit
import BigInt

public enum SRP6UtilError: Error {
	case invalidPublicValue
	case invalidBigIntValue
	case invalidHexStringValue
	case invalidDataValue
	case noAccessToKeychain
	case invalidM2Value
	case m2VaricationFailed
}

public enum CryptoError: Error {
	case invalidPublicValue
	case missingData(String)
	case verificationFailed
	case calculationError
}
