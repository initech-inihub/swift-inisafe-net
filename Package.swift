// swift-tools-version: 5.6
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "swift-inisafe-net",
    platforms: [
        .iOS(.v9)
    ],
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(
            name: "InisafeNet",
            targets: ["InisafeNet"]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        // .package(url: /* package url */, from: "1.0.0"),
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .binaryTarget(name: "iniNet", path: "Sources/XCFrameworks/iniNet.xcframework"),
        .binaryTarget(name: "iniPKI", path: "Sources/XCFrameworks/iniPKI.xcframework"),
        .binaryTarget(name: "iniCore", path: "Sources/XCFrameworks/iniCore.xcframework"),
        .binaryTarget(name: "Crypto", path: "Sources/XCFrameworks/Crypto.xcframework"),
        .target(
            name: "InisafeNet",
            dependencies: ["iniNet", "iniPKI", "iniCore", "Crypto"],
            path: "Sources"
        ),
        .testTarget(
            name: "swift-inisafe-netTests",
            dependencies: ["InisafeNet"]),
    ]
)
