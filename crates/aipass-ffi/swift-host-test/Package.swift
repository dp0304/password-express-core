// swift-tools-version:6.0
// SPDX-License-Identifier: Apache-2.0
//
// Host test package: links the macOS static library of aipass-ffi (built with the
// `test-support` feature by ../scripts/swift-host-test.sh) and the generated Swift
// bindings, then runs swift-testing scenarios through the real Rust core.
import Foundation
import PackageDescription

let libDir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
    .appendingPathComponent("lib").path

// Command Line Tools ship swift-testing as a framework outside the default search path.
let cltFrameworks = "/Library/Developer/CommandLineTools/Library/Developer/Frameworks"
let testingFlags: [SwiftSetting] = FileManager.default.fileExists(atPath: cltFrameworks)
    ? [.unsafeFlags(["-F", cltFrameworks])] : []
let testingLinker: [LinkerSetting] = FileManager.default.fileExists(atPath: cltFrameworks)
    ? [.unsafeFlags([
        "-F", cltFrameworks,
        "-Xlinker", "-rpath", "-Xlinker", cltFrameworks,
        // lib_TestingInterop.dylib, loaded by Testing.framework
        "-Xlinker", "-rpath", "-Xlinker", "/Library/Developer/CommandLineTools/Library/Developer/usr/lib",
    ])] : []

let package = Package(
    name: "AIPassCoreHostTest",
    platforms: [.macOS(.v14)],
    products: [.library(name: "AIPassCore", targets: ["AIPassCore"])],
    targets: [
        .target(
            name: "AIPassCoreFFI",
            path: "Sources/AIPassCoreFFI",
            linkerSettings: [
                .unsafeFlags(["-L", libDir]),
                .linkedLibrary("aipass_ffi"),
                .linkedFramework("Security"),
                .linkedFramework("SystemConfiguration"),
                .linkedFramework("CoreFoundation"),
            ]
        ),
        .target(
            name: "AIPassCore",
            dependencies: ["AIPassCoreFFI"],
            path: "Sources/AIPassCore",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        .testTarget(
            name: "AIPassCoreTests",
            dependencies: ["AIPassCore"],
            path: "Tests/AIPassCoreTests",
            swiftSettings: [.swiftLanguageMode(.v5)] + testingFlags,
            linkerSettings: testingLinker
        ),
    ]
)
