// swift-tools-version:4.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "PerfectLDAP",
    products: [
        .library(
            name: "PerfectLDAP",
            targets: ["PerfectLDAP"]),
    ],
    dependencies: [
        .package(url: "https://github.com/PerfectSideRepos/Perfect-ICONV.git", from: "3.0.0"),
        .package(url: "https://github.com/Altarix/Perfect-libSASL.git", from: "1.0.0"),
        .package(url: "https://github.com/Altarix/Perfect-OpenLDAP.git", from: "1.0.0"),
    ],
    targets: [
        .target(
            name: "PerfectLDAP",
            dependencies: ["PerfectICONV"]),
        .testTarget(
            name: "PerfectLDAPTests",
            dependencies: ["PerfectLDAP"]),
    ]
)
