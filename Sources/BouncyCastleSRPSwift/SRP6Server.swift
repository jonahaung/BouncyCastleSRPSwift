import Foundation
import CryptoKit
import BigInt

class SRP6Server {
	private var N: BigInt
	private var g: BigInt
	private var v: BigInt
	
	private var random: SecureRandom
	private var digest: SHA256Digest
	
	private var A: BigInt?
	private var b: BigInt?
	private var B: BigInt?
	private var u: BigInt?
	private var S: BigInt?
	private var M1: BigInt?
	private var M2: BigInt?
	private var Key: BigInt?
	
	init(N: BigInt, g: BigInt, v: BigInt, digest: SHA256Digest, random: SecureRandom) {
		self.N = N
		self.g = g
		self.v = v
		self.random = random
		self.digest = digest
	}
	
	func initialize(group: SRP6GroupParameters, v: BigInt, digest: SHA256Digest, random: SecureRandom) {
		self.N = group.N
		self.g = group.G
		self.v = v
		self.random = random
		self.digest = digest
	}
	
	func generateServerCredentials() throws -> BigInt {
		let k = SRP6Util.calculateK(digest: digest, N: N, g: g)
		self.b = try selectPrivateValue()
		
		let term1 = (k * v) % N
		let term2 = g.power(b!, modulus: N)
		self.B = (term1 + term2) % N
		
		return B!
	}
	
	func calculateSecret(clientA: BigInt) throws -> BigInt {
		self.A = try SRP6Util.validatePublicValue(N: N, val: clientA)
		self.u = SRP6Util.calculateU(digest: digest, N: N, A: A!, B: B!)
		self.S = try calculateS()
		
		return S!
	}
	
	private func selectPrivateValue() throws -> BigInt {
		return SRP6Util.generatePrivateValue(digest: digest, N: N, g: g, random: random)
	}
	
	private func calculateS() throws -> BigInt {
		let term1 = v.power(u!, modulus: N)
		let term2 = (term1 * A!) % N
		return term2.power(b!, modulus: N)
	}
	
	func verifyClientEvidenceMessage(clientM1: BigInt) throws -> Bool {
		guard let A = self.A, let B = self.B, let S = self.S else {
			throw CryptoError.missingData("Impossible to compute and verify M1: some data are missing from the previous operations (A,B,S)")
		}
		
		let computedM1 = SRP6Util.calculateM1(digest: digest, N: N, A: A, B: B, S: S)
		
		if computedM1 == clientM1 {
			self.M1 = clientM1
			return true
		}
		return false
	}
	
	func calculateServerEvidenceMessage() throws -> BigInt {
		guard let A = self.A, let M1 = self.M1, let S = self.S else {
			throw CryptoError.missingData("Impossible to compute M2: some data are missing from the previous operations (A,M1,S)")
		}
		
		self.M2 = SRP6Util.calculateM2(digest: digest, N: N, A: A, M1: M1, S: S)
		return M2!
	}
	
	func calculateSessionKey() throws -> BigInt {
		guard let S = self.S, let M1 = self.M1, let M2 = self.M2 else {
			throw CryptoError.missingData("Impossible to compute Key: some data are missing from the previous operations (S,M1,M2)")
		}
		
		self.Key = SRP6Util.calculateKey(digest: digest, N: N, S: S)
		return Key!
	}
}
