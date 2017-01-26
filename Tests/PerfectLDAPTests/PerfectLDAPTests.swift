import XCTest
@testable import PerfectLDAP
import Foundation
import PerfectICONV
import OpenLDAP

class PerfectLDAPTests: XCTestCase {
  let testURL = "ldap://192.168.56.13"
  let testUSR = "rocky@p.com"
  let testPWD = "rockford"
  let testRLM = "P"

  func testLogin() {
    do {
      let logfail = expectation(description: "logfail")
      let ldap = try LDAP(url: testURL, codePage: .GB2312)
      ldap.login(username: "abc", password: "123") { err in
        XCTAssertNotNil(err)
        logfail.fulfill()
        print("log failed passed")
      }//end log

      waitForExpectations(timeout: 10) { error in
        XCTAssertNil(error)
      }//end wait

      let logsuc = expectation(description: "logsuc")
      ldap.login(username: testUSR, password: testPWD) { err in
        XCTAssertNil(err)
        logsuc.fulfill()
        print("log real passed")
      }//end log
      waitForExpectations(timeout: 10) { error in
        XCTAssertNil(error)
      }//end wait


    }catch(let err) {
      XCTFail("testLogin error: \(err)")
    }
  }//end testLogin

  func testLoginSync() {
    do {
      let ldap = try LDAP(url: testURL, codePage: .GB2312)
      try ldap.login(username: "abc", password: "123")

      print("        --          --              ---            ---")
      print(ldap.supportedControl)
      print(ldap.supportedExtension)
      print(ldap.supportedSASLMechanisms)
    }catch {
      // bad password is supposed to fail.
    }

    do {
      let ldap = try LDAP(url: testURL, codePage: .GB2312)
      print("        --          --              ---            ---")
      try ldap.login(username: testUSR, password: testPWD)
    }catch(let err) {
      XCTFail("testLoginSync error: \(err)")
    }
  }//end testLogin


  func testSearch () {
    do {
      let ldap = try LDAP(url: testURL, username: testUSR, password: testPWD, codePage: .GB2312)

      let ser = expectation(description: "search")
      ldap.search(base:"cn=users,dc=p,dc=com", scope:.SUBTREE) { res in
        guard let r = res else {
          XCTFail("search return nil")
          return
        }//end guard
        print(r.dictionary)
        ser.fulfill()
      }//end search

      waitForExpectations(timeout: 10) { error in
        XCTAssertNil(error)
      }
    }catch(let err) {
      XCTFail("error: \(err)")
    }
  }
  func testSearchSync () {
    do {
      let ldap = try LDAP(url: testURL, username: testUSR, password: testPWD, codePage: .GB2312)
      guard let rs = try ldap.search(base:"cn=users,dc=p,dc=com",filter: "(initials=RW)", scope:.SUBTREE, attributes: ["cn", "company", "displayName", "initials"]) else {
        XCTFail("search failed")
        return
      }//end guard
      print("-------------------------------------------------------")
      print(rs.dictionary)
    }catch(let err) {
      XCTFail("error: \(err)")
    }

  }

  func testServerSort () {
    do {
      let ldap = try LDAP(url: testURL, username: testUSR, password: testPWD, codePage: .GB2312)
      print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
      let sort = LDAP.sortingString(sortedBy: [("displayName", .DSC), ("initials", .ASC)])
      print(sort)
      guard let res = try ldap.search(base:"cn=users,dc=p,dc=com",scope:.SUBTREE, attributes: ["displayName", "initials"], sortedBy: sort) else {
        XCTFail("server control failed")
        return
      }//end guard
      print(res.dictionary)
    }catch(let err) {
      XCTFail("server control: \(err)")
    }

  }

  func testAttributeMod () {
    do {
      let ldap = try LDAP(url: testURL, username: testUSR, password: testPWD, codePage: .GB2312)
      guard let rs = try ldap.search(base:"cn=users,dc=p,dc=com",filter: "(initials=RW)", scope:.SUBTREE) else {
        XCTFail("search failed")
        return
      }//end guard
      print("=======================================================")
      print(rs.dictionary)
      print("=======================================================")
      let mod = expectation(description: "search")
      ldap.modify(distinguishedName: "CN=Rockford Wei,CN=Users,DC=p,DC=com", attributes: ["mail":["rocky@perfect.org", "rockywei@gmx.com"], "otherMailbox":["rockywei524@gmail.com"]]) { err in
        mod.fulfill()
        XCTAssertNil(err)
      }//end add
      self.waitForExpectations(timeout: 10){ error in
        XCTAssertNil(error)
      }
      guard let res = try ldap.search(base:"cn=users,dc=p,dc=com",filter: "(initials=RW)", scope:.SUBTREE) else {
        XCTFail("search failed")
        return
      }//end guard
      print("=======================================================")
      print(res.dictionary)
      print("=======================================================")
    }catch(let err) {
      XCTFail("error: \(err)")
    }

  }

  func testSASLDefaults () {
    do {

      let ldap = try LDAP(url: testURL)

      let sasl = ldap.supportedSASL
      guard let gssapi = sasl[LDAP.AuthType.GSSAPI] else {
        XCTFail("GSSAPI FAULT")
        return
      }
      print(gssapi)

      guard let spnego = sasl[LDAP.AuthType.SPNEGO] else {
        XCTFail("SPNEGO FAULT")
        return
      }
      print(spnego)
      
      let r = ldap.withUnsafeSASLDefaultsPointer(mech: "GSSAPI", realm: "PERFECT") { ptr -> Int in
        guard let p = ptr else {
          return 0
        }//end if
        let pdef = unsafeBitCast(p, to: UnsafeMutablePointer<lutilSASLdefaults>.self)
        let def = pdef.pointee
        let mech = String(cString: def.mech)
        let realm = String(cString: def.realm)
        XCTAssertEqual(mech, "GSSAPI")
        XCTAssertEqual(realm, "PERFECT")
        return 100
      }//en r
      XCTAssertEqual(r, 100)
    }catch(let err) {
      XCTFail("error: \(err)")
    }
  }

  func testSASLogin() {
    do {

      let ldap = try LDAP(url: testURL)
      try ldap.login(username: testUSR, password: testPWD, realm: testRLM, auth: .GSSAPI)
    }catch(let err) {
      XCTFail("error: \(err)")
    }
  }

  static var allTests : [(String, (PerfectLDAPTests) -> () throws -> Void)] {
    return [
      ("testLogin", testLogin),
      ("testLoginSync", testLoginSync),
      ("testSearch", testSearch),
      ("testSearchSync", testSearchSync),
      ("testAttributeMod", testAttributeMod),
      ("testServerSort", testServerSort),
      ("testSASLDefaults", testSASLDefaults),
      ("testSASLogin", testSASLogin)
    ]
  }
}
