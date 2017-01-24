import XCTest
@testable import PerfectLDAP
import Foundation
import PerfectICONV

class PerfectLDAPTests: XCTestCase {
  let testURL = "ldap://192.168.56.13"
  let testUSR = "rocky@p.com"
  let testPWD = "rockford"

  func testLogin() {
    do {
      let logfail = expectation(description: "logfail")
      let ldap = try LDAP(url: testURL, codePage: .GB2312)
      ldap.login(username: "abc", password: "123") { result in
        XCTAssertFalse(result)
        logfail.fulfill()
        print("log failed passed")
      }//end log

      waitForExpectations(timeout: 10) { error in
        XCTAssertNil(error)
      }//end wait

      let logsuc = expectation(description: "logsuc")
      ldap.login(username: testUSR, password: testPWD) { result in
        XCTAssertTrue(result)
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
      let fail = ldap.login(username: "abc", password: "123")
      XCTAssertFalse(fail)

      let succ = ldap.login(username: testUSR, password: testPWD)
      XCTAssertTrue(succ)
    }catch(let err) {
      XCTFail("testLoginSync error: \(err)")
    }
  }//end testLogin


  func testSearch () {
    do {
      let ldap = try LDAP(url: "ldap://192.168.56.13", username: testUSR, password: testPWD, codePage: .GB2312)

      let ser = expectation(description: "search")
      ldap.search(base:"cn=users,dc=p,dc=com", scope:.SUBTREE) { res in
        guard let r = res else {
          XCTFail("search return nil")
          return
        }//end guard
        print(r)
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
      let ldap = try LDAP(url: "ldap://192.168.56.13", username: testUSR, password: testPWD, codePage: .GB2312)
      guard let rs = try ldap.search(base:"cn=users,dc=p,dc=com",filter: "(initials=RW)", scope:.SUBTREE, attributes: ["cn", "company", "displayName", "initials"]) else {
        XCTFail("search failed")
        return
      }//end guard
      print("-------------------------------------------------------")
      print(rs.dictionary)
      print("-------------------------------------------------------")
    }catch(let err) {
      XCTFail("error: \(err)")
    }
    
  }

  func testAttributeMod () {
    do {
      let ldap = try LDAP(url: "ldap://192.168.56.13", username: testUSR, password: testPWD, codePage: .GB2312)
      guard let rs = try ldap.search(base:"cn=users,dc=p,dc=com",filter: "(initials=RW)", scope:.SUBTREE) else {
        XCTFail("search failed")
        return
      }//end guard
      print("=======================================================")
      print(rs.dictionary)
      print("=======================================================")
      let add = expectation(description: "search")
      ldap.add(distinguishedName: "CN=Rockford Wei,CN=Users,DC=p,DC=com", attributes: ["mail":["rocky@perfect.org", "rockywei@gmx.com"], "otherMailbox":["rockywei524@gmail.com"]]) { err in
        add.fulfill()
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

  static var allTests : [(String, (PerfectLDAPTests) -> () throws -> Void)] {
    return [
      ("testLogin", testLogin),
      ("testLoginSync", testLoginSync),
      ("testSearch", testSearch),
      ("testSearchSync", testSearchSync),
      ("testAttributeMod", testAttributeMod)
    ]
  }
}
