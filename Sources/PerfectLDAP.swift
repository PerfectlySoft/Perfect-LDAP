//
//  PerfectLDAP.swift
//  PerfectLDAP
//
//  Created by Rocky Wei on 2017-01-17.
//	Copyright (C) 2017 PerfectlySoft, Inc.
//
//===----------------------------------------------------------------------===//
//
// This source file is part of the Perfect.org open source project
//
// Copyright (c) 2017 - 2018 PerfectlySoft Inc. and the Perfect project authors
// Licensed under Apache License v2.0
//
// See http://perfect.org/licensing.html for license information
//
//===----------------------------------------------------------------------===//
//

/// C library of OpenLDAP
import OpenLDAP

/// Threading Library
import PerfectThread

/// Iconv
import PerfectICONV

/// Perfect LDAP Module
public class LDAP {

  /// Searching Scope
  public enum Scope : ber_int_t {
    case BASE = 0, SINGLE_LEVEL = 1, SUBTREE = 2, CHILDREN = 3, DEFAULT = -1
  }//end

  /// Authentication Model
  public enum AuthType {
    /// username@domain & password
    case SIMPLE
    /// GSS-API
    case GSSAPI
    /// GSS-SPNEGO
    case SPNEGO
    /// DIGEST MD5
    case DIGEST
  }//end 

  /// Error Handling
  public enum Exception: Error {
    /// Error with Message
    case message(String)
  }//end enum

  public static func withCArrayOfString(array: [String] = [], operation: (UnsafeMutablePointer<UnsafeMutablePointer<Int8>?>?) -> Void) {

    if array.isEmpty {
      operation(nil)
      return
    }//end if

    // duplicate the array and append a null string
    var attr: [String?] = array
    attr.append(nil)

    // duplicate again and turn it into an array of pointers
    var parr = attr.map { $0 == nil ? nil : strdup($0!) }

    // perform the operation
    parr.withUnsafeMutableBufferPointer { operation($0.baseAddress) }

    // release allocated string pointers.
    for p in parr { free(UnsafeMutablePointer(mutating: p)) }
  }//end withCArrayOfString

  /// Explain the error code, typical usage is `throw Exception.message(LDAP.error(error_number))`
  /// - parameters:
  ///   - errno: Int32, the error number return by most ldap_XXX functions
  /// - returns:
  ///   a short text of explaination in English. *NOTE* string pointer of err2string is static so don't free it
  @discardableResult
  public static func error(_ errno: Int32) -> String {
    return String(cString: ldap_err2string(errno))
  }//end error

  /// time out value in terms of querying process, in seconds
  public var timeout: Int {
    get {
      var t = timeval(tv_sec: 0, tv_usec: 0)
      let _ = ldap_get_option(ldap, LDAP_OPT_TIMEOUT, &t)
      return t.tv_sec
    }//end get
    set {
      var t = timeval(tv_sec: timeout, tv_usec: 0)
      let _ = ldap_set_option(ldap, LDAP_OPT_TIMEOUT, &t)
    }//end set
  }//end timetout

  /// Searching result memory size limitations, for example, 1000 for 1000 lines?
  public var limitation: Int {
    get {
      var limit = 0
      let _ = ldap_get_option(ldap, LDAP_OPT_SIZELIMIT, &limit)
      return limit
    }//end get
    set {
      var limit = limitation
      let _ = ldap_set_option(ldap, LDAP_OPT_TIMEOUT, &limit)
    }//end set
  }//end limitation

  /// LDAP handler pointer
  internal var ldap: OpaquePointer? = nil

  /// codepage convertor
  internal var iconv: Iconv? = nil

  /// convert string if encoding is required
  /// - parameters:
  ///   - ber: struct berval of the original buffer
  /// - returns:
  ///   encoded string
  public func string(ber: berval) -> String {
    guard let i = iconv else {
      return String(validatingUTF8: ber.bv_val) ?? ""
    }//end i
    return i.convert(from: ber)
  }//end string

  /// convert string if encoding is required
  /// - parameters:
  ///   - pstr: pointer of the original buffer, will apply null-terminated method
  /// - returns:
  ///   encoded string
  public func string(pstr: UnsafeMutablePointer<Int8>) -> String {
    let ber = berval(bv_len: strlen(pstr), bv_val: pstr)
    return self.string(ber: ber)
  }//end ber

  /// constructor of LDAP. could be a simple LDAP() to local server or LDAP(url) with / without logon options.
  /// if login parameters were input, the process would block until finished.
  /// so it is strongly recommanded that call LDAP() without login option and call ldap.login() {} in async mode
  /// - parameters:
  ///   - url: String, something like ldap://somedomain.com:port
  ///   - username: String, user name to login, optional.
  ///   - password: String, password for login, optional.
  ///   - auth: AuthType, such as SIMPLE, GSSAPI, SPNEGO or DIGEST MD5
  ///   - codePage: object server coding page, e.g., GB2312, BIG5 or JS
  /// - throws:
  ///   possible exceptions of initial failed or access denied
  public init(url:String = "ldap://localhost", username: String? = nil, password: String? = nil, auth: AuthType = .SIMPLE, codePage: Iconv.CodePage = .UTF8) throws {

    if codePage != .UTF8 {
      do {
        iconv = try Iconv(from: codePage, to: .UTF8)
      }catch {

      }///end try
    }//end if

    ldap = OpaquePointer(bitPattern: 0)
    let r = ldap_initialize(&ldap, url)
    guard r == 0 else {
      throw Exception.message(LDAP.error(r))
    }//end guard

    // if no login required, skip.
    if username == nil || password == nil {
      return
    }//end if

    // call login internally
    guard login(username: username ?? "", password: password ?? "", auth: auth) else {
      throw Exception.message("Access Denied")
    }//end _login
  }//end init

  /// login in synchronized mode, will block the calling thread
  /// - parameters:
  ///   - username: String, user name to login, optional.
  ///   - password: String, password for login, optional.
  ///   - auth: AuthType, such as SIMPLE, GSSAPI, SPNEGO or DIGEST MD5
  /// - returns:
  ///   true for a successful login.
  @discardableResult
  public func login(username: String, password: String, auth: AuthType = .SIMPLE) -> Bool {
    var cred = berval(bv_len: ber_len_t(password.utf8.count), bv_val: ber_strdup(password))
    let r = ldap_sasl_bind_s(self.ldap, username, nil, &cred, nil, nil, nil)
    ber_memfree(cred.bv_val)
    return r == 0
  }//end login

  /// Login in asynchronized mode. Once completed, it would invoke the callback handler
  /// - parameters:
  ///   - username: String, user name to login, optional.
  ///   - password: String, password for login, optional.
  ///   - auth: AuthType, such as SIMPLE, GSSAPI, SPNEGO or DIGEST MD5
  ///   - completion: callback handler with a boolean parameter indicating whether login succeeded or not.
  public func login(username: String, password: String, auth: AuthType = .SIMPLE, completion: @escaping (Bool)->Void) {
    Threading.dispatch {
      let r = self.login(username: username, password: password, auth: auth)
      completion(r)
    }//end thread
  }//end login

  /// destructor of the class
  deinit {
    ldap_unbind_ext_s(ldap, nil, nil)
  }//end deinit


  /// Attribute of a searching result
  public struct Attribute {

    /// name of the attribute
    internal var _name = ""

    /// name of the attribute, read only
    public var name: String { get { return _name } }

    /// value set of the attribute, as an array of string
    internal var _values = [String]()

    /// value set of the attribute, as an array of string, read only
    public var values:[String] { get { return _values } }

    /// constructor of Attribute
    /// - parameters:
    ///   - ldap: the LDAP handler
    ///   - entry: the LDAPMessage (single element)
    ///   - tag: attribute name returned by ldap_xxx_attribute
    public init (ldap: LDAP, entry:OpaquePointer, tag:UnsafePointer<Int8>) {
      _name = String(cString: tag)
      let valueSet = ldap_get_values_len(ldap.ldap, entry, tag)
      var cursor = valueSet
      while(cursor != nil) {
        guard let pBer = cursor?.pointee else {
          break
        }//end guard
        let b = pBer.pointee
        _values.append(ldap.string(ber: b))
        cursor = cursor?.successor()
      }//end cursor
      if valueSet != nil {
        ldap_value_free_len(valueSet)
      }//end if
    }//end init
  }//end Attribute

  /// Attributes Set of a Searching result
  public struct AttributeSet {

    /// name of the attribute
    internal var _name = ""

    /// name of the attribute, read only
    public var name: String { get { return _name } }

    /// attribute value set array
    internal var _attributes = [Attribute]()

    /// attribute value set array, read only
    public var attributes: [Attribute] { get { return _attributes } }

    /// constructor of Attribute
    /// - parameters:
    ///   - ldap: the LDAP handler
    ///   - entry: the LDAPMessage (single element)
    public init (ldap: LDAP, entry:OpaquePointer) {
      guard let pName = ldap_get_dn(ldap.ldap, entry) else {
        return
      }//end pName
      _name = ldap.string(pstr: pName)
      ldap_memfree(pName)
      var ber = OpaquePointer(bitPattern: 0)
      var a = ldap_first_attribute(ldap.ldap, entry, &ber)
      while(a != nil) {
        _attributes.append(Attribute(ldap: ldap, entry: entry, tag: a!))
        ldap_memfree(a)
        a = ldap_next_attribute(ldap.ldap, entry, ber)
      }//end while
      ber_free(ber, 0)
    }//end init
  }//end class

  /// a reference record of an LDAP search result
  public struct Reference {

    /// value set in an array of string
    internal var _values = [String] ()

    /// value set in an array of string, read only
    public var values: [String] { get { return _values } }

    /// constructor of Reference
    /// - parameters:
    ///   - ldap: the LDAP handler
    ///   - reference: the LDAPMessage (single element)
    public init(ldap:LDAP, reference:OpaquePointer) {
      var referrals = UnsafeMutablePointer<UnsafeMutablePointer<Int8>?>(bitPattern: 0)

      // *NOTE* ldap_value_free is deprecated so have to use memfree in chain instead
      let r = ldap_parse_reference(ldap.ldap, reference, &referrals, nil, 0)
      guard r == 0 else {
        return
      }//end guard
      var cursor = referrals
      while(cursor != nil) {
        guard let pstr = cursor?.pointee else {
          break
        }//end guard
        _values.append(ldap.string(pstr: pstr))
        ldap_memfree(pstr)
        cursor = cursor?.successor()
      }//end while
      ldap_memfree(referrals)
    }//end init
  }//end struct

  /// LDAP Result record
  public struct Result {

    /// error code of result
    internal var _errCode = Int32(0)

    /// error code of result, read only
    public var errCode: Int { get { return Int(_errCode) } }

    /// error message
    internal var _errMsg = ""

    /// error message, read only
    public var errMsg: String { get { return _errMsg } }

    /// matched dn
    internal var _matched = ""

    /// matched dn, read only
    public var matched: String { get { return _matched } }

    /// referrals as an array of string
    internal var _ref = [String]()

    /// referrals as an array of string, read only
    public var referrals: [String] { get { return _ref } }
    
    /// constructor of Result
    /// - parameters:
    ///   - ldap: the LDAP handler
    ///   - result: the LDAPMessage (single element)
    public init(ldap:LDAP, result:OpaquePointer) {
      var emsg = UnsafeMutablePointer<Int8>(bitPattern: 0)
      var msg = UnsafeMutablePointer<Int8>(bitPattern: 0)
      var ref = UnsafeMutablePointer<UnsafeMutablePointer<Int8>?>(bitPattern: 0)
      let r = ldap_parse_result(ldap.ldap, result, &_errCode, &msg, &emsg, &ref, nil, 0)
      guard r == 0 else {
        return
      }//end guard
      if msg != nil {
        _matched = ldap.string(pstr: msg!)
        ldap_memfree(msg)
      }//end if
      if emsg != nil {
        _errMsg = ldap.string(pstr: emsg!)
        ldap_memfree(emsg)
      }//end if
      var rf = ref
      while(rf != nil) {
        guard let p = rf?.pointee else {
          break
        }
        _ref.append(ldap.string(pstr: p))
        ldap_memfree(p)
        rf = rf?.successor()
      }//end rf
      if ref != nil {
        ldap_memfree(ref)
      }//end if
    }//end Result
  }
  /// Result set of a searching query
  public struct ResultSet {

    /// attribute set as an array
    internal var _attr = [AttributeSet]()

    /// attribute set as an array, read only
    public var attributeSet: [AttributeSet] { get { return _attr } }

    /// as an dictionary, read only
    public var dictionary:[String:[String:Any]] { get {
      var dic:[String:[String:Any]] = [:]
      for aset in _attr {
        var d: [String: Any] = [:]
        for a in aset.attributes {
          if a.values.count > 1 {
            d[a.name] = a.values
          }else {
            d[a.name] = a.values[0]
          }//end if
        }//next a
        dic[aset.name] = d
      }//next aset
      return dic
    } } //end simple

    /// references as an array
    internal var _ref = [Reference]()

    /// references as an array, read only
    public var references: [Reference] { get { return _ref } }

    /// results as an array of result
    internal var _results = [Result]()

    /// results as an array of result, read only
    public var result: [Result] { get { return _results } }

    /// constructor of Attribute
    /// - parameters:
    ///   - ldap: the LDAP handler
    ///   - chain: the LDAPMessage chain elements
    public init (ldap: LDAP, chain:OpaquePointer) {
      var m = ldap_first_message(ldap.ldap, chain)
      while(m != nil) {
        switch(UInt(ldap_msgtype(m))) {
        case LDAP_RES_SEARCH_ENTRY:
          _attr.append(AttributeSet(ldap: ldap, entry: m!))
        case LDAP_RES_SEARCH_REFERENCE:
          _ref.append(Reference(ldap: ldap, reference: m!))
        case LDAP_RES_SEARCH_RESULT:
          _results.append(Result(ldap: ldap, result: m!))
        default:
          ()
        }//end case
        m = ldap_next_message(ldap.ldap, m)
      }//end while
    }//end init
  }//end struct

  /// synchronized search
  /// - parameters: 
  ///   - base: String, search base domain (dn), default = ""
  ///   - filter: String, the filter of query, default = "(objectclass=*)", means all possible results
  ///   - scope: See Scope, BASE, SINGLE_LEVEL, SUBTREE or CHILDREN
  /// - returns:
  ///   ResultSet. See ResultSet
  /// - throws:
  ///   Exception.message
  @discardableResult
  public func search(base:String = "", filter:String = "(objectclass=*)", scope:Scope = .BASE, attributes: [String] = []) throws -> ResultSet? {

    // prepare the return set
    var msg = OpaquePointer(bitPattern: 0)

    // prepare the return value
    var r = Int32(0)

    LDAP.withCArrayOfString(array: attributes) { pAttribute in

      // perform the search
      r = ldap_search_ext_s(self.ldap, base, scope.rawValue, filter, pAttribute, 0, nil, nil, nil, 0, &msg)
    }//end

    // validate the query
    guard r == 0 && msg != nil else {
      throw Exception.message(LDAP.error(r))
    }//next

    // process the result set
    let rs = ResultSet(ldap: self, chain: msg!)

    // release the memory
    ldap_msgfree(msg)

    return rs
  }//end search

  /// asynchronized search
  /// - parameters:
  ///   - base: String, search base domain (dn), default = ""
  ///   - filter: String, the filter of query, default = "(objectclass=*)", means all possible results
  ///   - scope: See Scope, BASE, SINGLE_LEVEL, SUBTREE or CHILDREN
  ///   - completion: callback with a parameter of ResultSet, nil if failed
  @discardableResult
  public func search(base:String = "", filter:String = "(objectclass=*)", scope:Scope = .BASE, completion: @escaping (ResultSet?)-> Void) {
    Threading.dispatch {
      do {
        completion(try self.search(base: base, filter: filter, scope: scope))
      }catch {
        completion(nil)
      }//end catch
    }//end threading
  }//end search
}//end class
















