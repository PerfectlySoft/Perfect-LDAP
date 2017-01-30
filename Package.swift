import PackageDescription

let package = Package(
    name: "PerfectLDAP",
    dependencies:[
      .Package(url: "https://github.com/PerfectSideRepos/Perfect-ICONV.git", majorVersion: 1),
      .Package(url:"https://github.com/PerfectlySoft/Perfect-Thread.git", majorVersion: 2),
      .Package(url:"https://github.com/PerfectlySoft/Perfect-libSASL.git", majorVersion: 1),
      .Package(url:"https://github.com/PerfectlySoft/Perfect-OpenLDAP.git", majorVersion: 1)
    ]
)
