# Perfect-LDAP [简体中文](README.zh_CN.md)

<p align="center">
    <a href="http://perfect.org/get-involved.html" target="_blank">
        <img src="http://perfect.org/assets/github/perfect_github_2_0_0.jpg" alt="Get Involed with Perfect!" width="854" />
    </a>
</p>

<p align="center">
    <a href="https://github.com/PerfectlySoft/Perfect" target="_blank">
        <img src="http://www.perfect.org/github/Perfect_GH_button_1_Star.jpg" alt="Star Perfect On Github" />
    </a>  
    <a href="http://stackoverflow.com/questions/tagged/perfect" target="_blank">
        <img src="http://www.perfect.org/github/perfect_gh_button_2_SO.jpg" alt="Stack Overflow" />
    </a>  
    <a href="https://twitter.com/perfectlysoft" target="_blank">
        <img src="http://www.perfect.org/github/Perfect_GH_button_3_twit.jpg" alt="Follow Perfect on Twitter" />
    </a>  
    <a href="http://perfect.ly" target="_blank">
        <img src="http://www.perfect.org/github/Perfect_GH_button_4_slack.jpg" alt="Join the Perfect Slack" />
    </a>
</p>

<p align="center">
    <a href="https://developer.apple.com/swift/" target="_blank">
        <img src="https://img.shields.io/badge/Swift-3.0-orange.svg?style=flat" alt="Swift 3.0">
    </a>
    <a href="https://developer.apple.com/swift/" target="_blank">
        <img src="https://img.shields.io/badge/Platforms-OS%20X%20%7C%20Linux%20-lightgray.svg?style=flat" alt="Platforms OS X | Linux">
    </a>
    <a href="http://perfect.org/licensing.html" target="_blank">
        <img src="https://img.shields.io/badge/License-Apache-lightgrey.svg?style=flat" alt="License Apache">
    </a>
    <a href="http://twitter.com/PerfectlySoft" target="_blank">
        <img src="https://img.shields.io/badge/Twitter-@PerfectlySoft-blue.svg?style=flat" alt="PerfectlySoft Twitter">
    </a>
    <a href="http://perfect.ly" target="_blank">
        <img src="http://perfect.ly/badge.svg" alt="Slack Status">
    </a>
</p>

This project provides an express OpenLDAP class wrapper which enable access to OpenLDAP servers and Windows Active Directory server.

This package builds with Swift Package Manager and is part of the [Perfect](https://github.com/PerfectlySoft/Perfect) project.

Ensure you have installed and activated the latest Swift 3.0 tool chain.

## Quick Start

Add the following dependency to your project's Package.swift file:

``` swift
.Package(url: "https://github.com/PerfectlySoft/Perfect-LDAP.git", majorVersion: 1)
```

Then import PerfectLDAP to your source code:

``` swift
import PerfectLDAP
```

## Login Options

PerfectLDAP provides a special object called `LDAP.login` to store essential account information for LDAP connections and the form of constructor is subject to the authentication types:

### Simple Login

To use simple login method, simply call `LDAP.login(binddn: String, password: String)`, as snippet below:

``` swift
let credential = LDAP.Login(binddn: "CN=judy,CN=Users,DC=perfect,DC=com", password: "0penLDAP")
```

### Digest-MD5 (*EXPERIMENTAL*)

To apply Digest-MD5 interactive login, call `LDAP.login(authname: String, user: String, password: String, realm: String)` as demo below:
``` swift
let credential = LDAP.Login(authname: "judy", user: "DN:CN=judy,CN=Users,DC=perfect,DC=com", password: "0penLDAP", realm: "PERFECT.COM")
```
*NOTE* The `authname` is equivalent to `SASL_CB_AUTHNAME` and `user` is actually the macro of `SASL_CB_USER`. If any parameter above is not applicable to your case, simply assign an empty string "" to ignore it.

### GSSAPI and GSS-SPNEGO (*EXPERIMENTAL*)

To apply GSSAPI / GSS-SPNEGO authentication, call `LDAP.login(mechanism: AuthType)` to construct a login credential:

``` swift
// this call will generate a GSSAPI login credential
let credential = LDAP.login(mechanism: .GSSAPI)
```
or

``` swift
// this call will generate a GSS-SPNEGO login credential
let credential = LDAP.login(mechanism: .SPNEGO)
```

## Connect to LDAP Server

You can create actual connections as need with or without login credential. The full API is `LDAP(url:String, loginData: Login?, codePage: Iconv.CodePage)`.

### TLS Option

You can choose either `ldap://` or `ldaps://` for connections, as demo below:

``` swift
// this will connect to a 389 port without any encryption
let ld = try LDAP(url: "ldap://perfect.com")
```
or,

``` swift
// this will connect to a 636 port with certificates
let ld = try LDAP(url: "ldaps://perfect.com")
```

### Login or Anonymous

Connection with login credential will block the main thread until timeout.

``` swift
// this snippet demonstrate how to connect to LDAP server with a login credential
// create login credential
let url = "ldaps://..."
let credential = LDAP.login( ... )
let connection = try LDAP(url: url, loginData: login)
```
However, a two phased threading login process could also bring more controls to the application:

``` swift
// first create a connection
let connection = try LDAP(url: "ldaps:// ...")

// set the timeout for communication. In this example, connection will be timeout in ten seconds.
connection.timeout = 10

// setup login info
let credential = LDAP.login( ... )

// login in a separated thread
connection.login(info: credential) { err in
  // if err is not nil, then something must be wrong in the login process.
}
```

## Search

PerfectLDAP provides asynchronous and synchronous version of searching API with the same parameters:

### Synchronous Search

``` swift
LDAP.search(base:String, filter:String, scope:Scope, attributes: [String], sortedBy: String) throws -> [String:[String:Any]]
```

### Asynchronous Search
``` swift
LDAP.search(base:String, filter:String, scope:Scope, attributes: [String], sortedBy: String, , completion: @escaping ([String:[String:Any]])-> Void)
```

### Parameters of Search
- base: String, search base domain (dn), default = ""
- filter: String, the filter of query, default = "(objectclass=*)", means all possible results
- scope: Searching Scope, i.e., .BASE, .SINGLE_LEVEL, .SUBTREE or .CHILDREN
- sortedBy: a sorting string, may also be generated by LDAP.sortingString()
- completion: callback with a parameter of dictionary, empty if failed

### Server Side Sort (*EXPERIMENTAL*)
The `sortedBy` parameters is a string that indicates the remote server to perform search with a sorted set. PerfectLDAP provides a more verbal way to build such a string, i.e, an array of tuples to describe what attributes would control the result set:

``` swift
// each tuple consists two parts: the sorting field and its order - .ASC or .DSC
let sort = LDAP.sortingString(sortedBy: [("description", .ASC)])
```

## Issues

We are transitioning to using JIRA for all bugs and support related issues, therefore the GitHub issues has been disabled.

If you find a mistake, bug, or any other helpful suggestion you'd like to make on the docs please head over to [http://jira.perfect.org:8080/servicedesk/customer/portal/1](http://jira.perfect.org:8080/servicedesk/customer/portal/1) and raise it.

A comprehensive list of open issues can be found at [http://jira.perfect.org:8080/projects/ISS/issues](http://jira.perfect.org:8080/projects/ISS/issues)

## Further Information
For more information on the Perfect project, please visit [perfect.org](http://perfect.org).
