// swift-tools-version: 6.1
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
	name: "BouncyCastleSRPSwift",
	platforms: [.iOS(.v14)],
	products: [
		.library(
			name: "BouncyCastleSRPSwift",
			targets: ["BouncyCastleSRPSwift"]),
	],
	dependencies: [
		.package(url: "https://github.com/attaswift/BigInt.git", from: "5.4.0")
	],
	targets: [
		.target(
			name: "BouncyCastleSRPSwift",
			dependencies: [
				.product(name: "BigInt", package: "BigInt")

			]
		),
		.testTarget(
			name: "BouncyCastleSRPSwiftTests",
			dependencies: ["BouncyCastleSRPSwift"]
		),
	]
)
