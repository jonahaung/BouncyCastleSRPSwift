import Foundation
import CryptoKit
import BigInt

enum SRP6UtilError: Error {
	case invalidPublicValue
	case invalidBigIntValue
	case invalidHexStringValue
	case invalidDataValue
	case noAccessToKeychain
	case invalidM2Value
	case m2VaricationFailed
}

enum CryptoError: Error {
	case invalidPublicValue
	case missingData(String)
	case verificationFailed
	case calculationError
}
