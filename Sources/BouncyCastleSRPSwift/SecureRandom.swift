import Foundation

protocol SecureRandom {
	func generateBytes(count: Int) -> Data
}

struct SystemRandom: SecureRandom {
    func generateBytes(count: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        _ = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        return Data(bytes)
    }
}
