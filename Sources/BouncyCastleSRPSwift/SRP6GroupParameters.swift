import Foundation
import BigInt

struct SRP6GroupParameters {
	let N: BigInt
	let G: BigInt
	
	init(N: BigInt, G: BigInt) {
		self.N = N
		self.G = G
	}
}
