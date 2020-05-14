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

/// C library of SASL
import SASL

/// C library of OpenLDAP
import OpenLDAP

/// Iconv
import PerfectICONV

import Dispatch

/// Perfect LDAP Module
public class LDAP {

  /// Searching Scope
  public enum Scope : ber_int_t {
    case BASE = 0, SINGLE_LEVEL = 1, SUBTREE = 2, CHILDREN = 3, DEFAULT = -1
  }//end

  let threading = DispatchQueue(label: "ldap.thread.\(time(nil))")

  /// Authentication Model
  public enum AuthType:String {
    /// username@domain & password
    case SIMPLE = ""
    /// GSS-API
    case GSSAPI = "GSSAPI"
    /// GSS-SPNEGO
    case SPNEGO = "GSS-SPNEGO"
    /// DIGEST MD5
    case DIGEST = "DIGEST-MD5"
    /// OTHER
    case OTHER = "UNSUPPORTED"
  }//end


  /// Login Data
  public class Login {

    /// the name of SASL_CB_AUTHNAME, the username to authenticate,
    /// without any symbols or suffix, usually a lowercased short name "someone"
    public var authname = "" // "Someone"

    /// distinguished name, usually in form of "CN=Someone,CN=User,CN=domain,CN=com"
    public var binddn = ""

    /// the name of SASL_CB_USER, the username to use for proxy authorization
    /// usually with a prefix of "dn=" with binddn: "DN:CN=Someone,CN=User,CN=domain,CN=com"
    public var user = ""

    /// the password of login
    public var password = ""

    /// the name of SASL_CB_GETREALM, the realm for the authentication attempt
    public var realm = ""

    /// mechanism for authentication
    public var mechanism: AuthType = .SIMPLE

    /// garbage manager
    internal var trashcan: [UnsafeMutablePointer<Int8>?] = []

    public func drop(garbage: UnsafeMutablePointer<Int8>?) { trashcan.append(garbage) }

    /// contructor for simple login
    /// - parameters:
    ///   - binddn: distinguished name, usually in form of "CN=Someone,CN=User,CN=domain,CN=com"
    ///   - password: the password
    public init(binddn: String = "", password: String = "") {
      self.binddn = binddn
      self.password = password
      self.mechanism = .SIMPLE
    }//end init

    /// constructor for SASL
    /// - parameters:
    ///   - authname: the name of SASL_CB_AUTHNAME, the username to authenticate, without any symbols or suffix, usually a lowercased short name "someone"
    ///   - user: the name of SASL_CB_USER, the username to use for proxy authorization, usually with a prefix of "dn=" with binddn: "DN:CN=Someone,CN=User,CN=domain,CN=com"
    ///   - password: the password of login
    ///   - realm: the name of SASL_CB_GETREALM, the realm for the authentication attempt
    ///   - mechanism: the SASL mechanism
    public init(authname: String = "", user: String = "", password: String = "", realm: String = "", mechanism: AuthType = .GSSAPI) {
      self.binddn = ""
      self.authname = authname
      self.user = user
      self.password = password
      self.realm = realm
      self.mechanism = mechanism
    }//end init

    deinit {
      for garbage in trashcan {
        if garbage == nil {
          continue
        }//end if
        ber_memfree(garbage)
      }//next
      trashcan.removeAll()
    }//end
  }//end Login

  /// Error Handling
  public enum Exception: Error {
    /// Error with Message
    case message(String)
  }//end enum

  /// Explain the error code, typical usage is `throw Exception.message(LDAP.error(error_number))`
  /// - parameters:
  ///   - errno: Int32, the error number return by most ldap_XXX functions
  /// - returns:
  ///   a short text of explaination in English. *NOTE* string pointer of err2string is static so don't free it
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
      var t = timeval(tv_sec: newValue, tv_usec: 0)
      let _ = ldap_set_option(ldap, LDAP_OPT_TIMEOUT, &t)
    }//end set
  }//end timetout

  /// the maximum number of entries that can be returned on a search operation
  public var limitation: Int {
    get {
      var limit = 0
      let _ = ldap_get_option(ldap, LDAP_OPT_SIZELIMIT, &limit)
      return limit
    }//end get
    set {
      var limit = newValue
      let _ = ldap_set_option(ldap, LDAP_OPT_SIZELIMIT, &limit)
    }//end set
  }//end limitation

  /// LDAP handler pointer
  internal var ldap: OpaquePointer? = nil

  /// codepage convertor
  internal var iconv: Iconv? = nil

  /// codepage reversely convertor
  internal var iconvR: Iconv? = nil

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
    let ber = berval(bv_len: ber_len_t(strlen(pstr)), bv_val: pstr)
    return self.string(ber: ber)
  }//end ber

  /// convert string to encoded binary data reversely
  /// *NOTE* MUST BE FREE MANUALLY
  /// - parameters:
  ///   - str: source utf8 string
  /// - returns:
  ///   encoded berval structure
  public func string(str: String) -> berval {
    guard let i = iconvR else {
      return str.withCString { ptr -> berval in
        return berval(bv_len: ber_len_t(str.utf8.count), bv_val: ber_strdup(ptr))
      }//end str
    }//end str
    return str.withCString { ptr -> berval in
      let (p, sz) = i.convert(buf: ptr, length: str.utf8.count)
      return berval(bv_len: ber_len_t(sz), bv_val: p)
    }//end str
  }//end string

  /// constructor of LDAP. could be a simple LDAP() to local server or LDAP(url) with / without logon options.
  /// if login parameters were input, the process would block until finished.
  /// so it is strongly recommanded that call LDAP() without login option and call ldap.login() {} in async mode
  /// - parameters:
  ///   - url: String, something like ldap://somedomain.com:port or ldaps://somedomain.com
  ///   - login: login data.
  ///   - codePage: object server coding page, e.g., GB2312, BIG5 or JS
  /// - throws:
  ///   possible exceptions of initial failed or access denied
  public init(url:String = "ldaps://localhost", loginData: Login? = nil, codePage: Iconv.CodePage = .UTF8) throws {

    if codePage != .UTF8 {
      // we need a pair of code pages to transit in both directions.
      iconv = try Iconv(from: codePage, to: .UTF8)
      iconvR = try Iconv(from: .UTF8, to: codePage)
    }//end if

    ldap = OpaquePointer(bitPattern: 0)
    var r = ldap_initialize(&ldap, url)

    guard r == 0 else {
      throw Exception.message(LDAP.error(r))
    }//end guard

    var proto = LDAP_VERSION3

    r = ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &proto)

    // if no login required, skip.
    if loginData == nil {
      return
    }//end if

    // call login internally
    try login(info: loginData)
  }//end init

  /// login in synchronized mode, will block the calling thread
  /// - parameters:
  ///   - info: login data
  /// - throws:
  ///   Exception message
  
  public func login(info: Login?) throws {

    // load login data
    guard let inf = info else {
      throw Exception.message("LOGIN DATA NOT AVAILABLE")
    }//end guard

    // prepare return value
    var r = Int32(0)

    // prepare an empty credential structure
    var cred = berval(bv_len: 0, bv_val: UnsafeMutablePointer<Int8>(bitPattern: 0))

    if inf.mechanism == .OTHER {
      throw Exception.message("UNSUPPORTED MECHANISMS")
    }//end if

    if inf.mechanism == .SIMPLE {
      // simple auth just use password and binddn to login
      cred.bv_val = ber_strdup(inf.password)
      cred.bv_len = ber_len_t(strlen(cred.bv_val))
      r = ldap_sasl_bind_s(self.ldap, inf.binddn, nil, &cred, nil, nil, nil)
      ber_memfree(cred.bv_val)
      if r == 0 {
        return
      }else {
        throw Exception.message(LDAP.error(r))
      }//end
    }//end if

    // turn the login info data into a pointer by this one.
    var pinf = inf

    // call the binding
    r = ldap_sasl_interactive_bind_s(self.ldap, inf.binddn, inf.mechanism.rawValue, nil, nil, LDAP_SASL_QUIET, { ld, flags, pRawDefaults, pRawInteract -> Int32 in

      // in this callback, convert the pointer of pointers back to defaults
      let pDef = unsafeBitCast(pRawDefaults, to: UnsafeMutablePointer<Login>.self)
      let pInt = unsafeBitCast(pRawInteract, to: UnsafeMutablePointer<sasl_interact_t>.self)
      let def = pDef.pointee
      var pcursor:UnsafeMutablePointer<sasl_interact_t>? = nil
      var interact: sasl_interact_t
      pcursor = pInt

      // loop & answer the question asked by server
      while(pcursor != nil) {
        interact = (pcursor?.pointee)!

        // prepare a blank pointer
        var dflt = ""
        switch(Int32(interact.id)) {
        case SASL_CB_AUTHNAME:
          dflt = def.authname
        case SASL_CB_USER:
          dflt = def.user
        case SASL_CB_PASS:
          dflt = def.password
        case SASL_CB_GETREALM:
          dflt = def.realm
        case SASL_CB_LIST_END:
          return 0
        case SASL_CB_NOECHOPROMPT, SASL_CB_ECHOPROMPT:
          dflt = ""
        default:
          return 0
        }//end case

        // once
        if !dflt.isEmpty {
          let str = ber_strdup(dflt)
          interact.result = unsafeBitCast(str, to: UnsafeRawPointer.self)
          interact.len = UInt32(dflt.utf8.count)
          def.drop(garbage: str)
        }else{
          interact.len = 0
        }//end if
        pcursor?.pointee = interact
        pcursor = pcursor?.successor()
      }//end while
      return 0
    }, UnsafeMutableRawPointer(UnsafeMutablePointer(mutating: &pinf)))

    if r == 0 {
      return
    }else {
      throw Exception.message(LDAP.error(r))
    }//end
  }//end login

  /// Login in asynchronized mode. Once completed, it would invoke the callback handler
  /// - parameters:
  ///   - info: login data
  ///   - completion: callback handler with a boolean parameter indicating whether login succeeded or not.
  public func login(info: Login, completion: @escaping (String?)->Void) {
    threading.async {
      do {
        try self.login(info: info)
        completion(nil)
      }catch(let err) {
        completion("LOGIN FAILED: \(err)")
      }//end do
    }//end thread
  }//end login

  /// destructor of the class
  deinit {
    ldap_unbind_ext_s(ldap, nil, nil)
  }//end deinit


  /// Attribute of a searching result
  internal struct Attribute {

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
  internal struct AttributeSet {

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
  internal struct Reference {

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
  internal struct Result {

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
  internal struct ResultSet {

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

  /// constant to indicate a sorting order: ascendant or descendant.
  public enum SortingOrder {
    case ASC
    case DSC
  }//end SortingOrder

  /// generate a standard sorting string from a series of fields
  /// - parameters:
  ///   - sortedBy: an array of tuple, which tells each field to sort in what order
  /// - returns:
  ///   the sorting language, as a string
  public static func sortingString( sortedBy: [(String, SortingOrder)] = [] ) -> String {
    return sortedBy.reduce("") { previous, next in
      let str = next.1 == .ASC ? next.0 : "-" + next.0
      return previous.isEmpty ? str : previous + " " + str
    }//end reduce
  }//end sortingString

  /// synchronized search
  /// - parameters:
  ///   - base: String, search base domain (dn), default = ""
  ///   - filter: String, the filter of query, default = "(objectclass=*)", means all possible results
  ///   - scope: See Scope, BASE, SINGLE_LEVEL, SUBTREE or CHILDREN
  ///   - sortedBy: a sorting string, may be generated by LDAP.sortingString()
  /// - returns:
  ///   ResultSet. See ResultSet
  /// - throws:
  ///   Exception.message
  public func search(base:String = "", filter:String = "(objectclass=*)", scope:Scope = .BASE, attributes: [String] = [], sortedBy: String = "") throws -> [String:[
  String:Any]] {

    var serverControl = UnsafeMutablePointer<LDAPControl>(bitPattern: 0)

    if !sortedBy.isEmpty {
      var sortKeyList = UnsafeMutablePointer<UnsafeMutablePointer<LDAPSortKey>?>(bitPattern: 0)
      let sortString = ber_strdup(sortedBy)
      var r = ldap_create_sort_keylist(&sortKeyList, sortString)
      defer { ber_memfree(sortString) }
      guard r == 0 else {
        throw Exception.message(LDAP.error(r))
      }//end if

      r = ldap_create_sort_control(self.ldap, sortKeyList, 0, &serverControl)
      defer { ldap_free_sort_keylist(sortKeyList) }
      guard r == 0 else {
        throw Exception.message(LDAP.error(r))
      }//end if
    }//end if

    // prepare the return set
    var msg = OpaquePointer(bitPattern: 0)

    let r = withCArrayOfString(array: attributes) { pAttribute -> Int32 in

      // perform the search
      let result = ldap_search_ext_s(self.ldap, base, scope.rawValue, filter, pAttribute, 0, &serverControl, nil, nil, 0, &msg)

      if serverControl != nil {
        ldap_control_free(serverControl)
      }
      return result
    }//end

    if let m = msg {
      // process the result set
      let rs = ResultSet(ldap: self, chain: m)

      // release the memory
      ldap_msgfree(m)

      return rs.dictionary
    }

    throw Exception.message(LDAP.error(r))
  }//end search

  /// asynchronized search
  /// - parameters:
  ///   - base: String, search base domain (dn), default = ""
  ///   - filter: String, the filter of query, default = "(objectclass=*)", means all possible results
  ///   - scope: See Scope, BASE, SINGLE_LEVEL, SUBTREE or CHILDREN
  ///   - sortedBy: a sorting string, may be generated by LDAP.sortingString()
  ///   - completion: callback with a parameter of ResultSet, nil if failed
  
  public func search(base:String = "", filter:String = "(objectclass=*)", scope:Scope = .BASE, sortedBy: String = "", completion: @escaping ([String:[String:Any]])-> Void) {
    threading.async {
      var rs: [String:[String:Any]] = [:]
      do {
        rs = try self.search(base: base, filter: filter, scope: scope, sortedBy: sortedBy)
      }catch {
        rs = [:]
      }//end catch
      completion(rs)
    }//end threading
  }//end search

  /// allocate a modification structure for internal usage
  /// - parameters:
  ///   - method: method of modification, i.e., LDAP_MOD_ADD or LDAP_MOD_REPLACE or LDAP_MOD_DELETE and LDAP_MOD_BVALUES
  ///   - key: attribute name to modify
  ///   - values: attribute values as an array
  /// - returns:
  ///   an LDAPMod structure
  internal func modAlloc(method: Int32, key: String, values: [String]) -> LDAPMod {
    let pValues = values.map { self.string(str: $0) }
    let pointers = pValues.asUnsafeNullTerminatedPointers()
    return LDAPMod(mod_op: method, mod_type: ber_strdup(key), mod_vals: mod_vals_u(modv_bvals: pointers))
  }//end modAlloc

  /// add an attribute to a DN
  /// - parameters:
  ///   - distinguishedName: specific DN
  ///   - attributes: attributes as an dictionary to add
  /// - throws:
  ///   - Exception with message, such as no permission, or object class violation, etc.
  
  public func add(distinguishedName: String, attributes: [String:[String]]) throws {

    // map the keys to an array
    let keys:[String] = attributes.keys.map { $0 }

    // map the key array to a modification array
    let mods:[LDAPMod] = keys.map { self.modAlloc(method: LDAP_MOD_ADD | LDAP_MOD_BVALUES, key: $0, values: attributes[$0]!)}

    // get the pointers
    let pMods = mods.asUnsafeNullTerminatedPointers()

    // perform adding
    let r = ldap_add_ext_s(self.ldap, distinguishedName, pMods, nil, nil)

    // release memory
    ldap_mods_free(pMods, 0)

    guard r == 0 else {
      throw Exception.message(LDAP.error(r))
    }//end if
  }//end func

  /// add an attribute to a DN
  /// - parameters:
  ///   - distinguishedName: specific DN
  ///   - attributes: attributes as an dictionary to add
  ///   - completion: callback once done. If something wrong, an error message will pass to the closure.
  
  public func add(distinguishedName: String, attributes: [String:[String]],completion: @escaping (String?)-> Void) {

    threading.async {
      do {
        // perform adding
        try self.add(distinguishedName: distinguishedName, attributes: attributes)

        // if nothing wrong, callback
        completion(nil)

      }catch(let err) {

        // otherwise callback an error
        completion("\(err)")
      }//end do

    }//end dispatch
  }//end func

  /// modify an attribute to a DN
  /// - parameters:
  ///   - distinguishedName: specific DN
  ///   - attributes: attributes as an dictionary to modify
  ///   - method: specify if an attribute should be added, removed or replaced (default)
  ///       add:     LDAP_MOD_ADD | LDAP_MOD_BVALUES
  ///       remove:  LDAP_MOD_DELETE | LDAP_MOD_BVALUES
  ///       replace: LDAP_MOD_REPLACE | LDAP_MOD_BVALUES
  /// - throws:
  ///   - Exception with message, such as no permission, or object class violation, etc.

  public func modify(distinguishedName: String, attributes: [String:[String]], method: Int32 = LDAP_MOD_REPLACE | LDAP_MOD_BVALUES) throws {

    // map the keys to an array
    let keys:[String] = attributes.keys.map { $0 }

    // map the key array to a modification array
    let mods:[LDAPMod] = keys.map { self.modAlloc(method: method, key: $0, values: attributes[$0]!)}

    // get the pointers
    let pMods = mods.asUnsafeNullTerminatedPointers()

    // perform modification
    let r = ldap_modify_ext_s(self.ldap, distinguishedName, pMods, nil, nil)

    // release memory
    ldap_mods_free(pMods, 0)

    guard r == 0 else {
      throw Exception.message(LDAP.error(r))
    }//end if
  }//end func

  /// modify an attribute to a DN
  /// - parameters:
  ///   - distinguishedName: specific DN
  ///   - attributes: attributes as an dictionary to modify
  ///   - completion: callback once done. If something wrong, an error message will pass to the closure.
  ///   - method: specify if an attribute should be added, removed or replaced (default)
  ///       add:     LDAP_MOD_ADD | LDAP_MOD_BVALUES
  ///       remove:  LDAP_MOD_DELETE | LDAP_MOD_BVALUES
  ///       replace: LDAP_MOD_REPLACE | LDAP_MOD_BVALUES
  
  public func modify(distinguishedName: String, attributes: [String:[String]],completion: @escaping (String?)-> Void, method: Int32 = LDAP_MOD_REPLACE | LDAP_MOD_BVALUES) {
    threading.async {
      do {
        // perform adding
        try self.modify(distinguishedName: distinguishedName, attributes: attributes, method: method)

        // if nothing wrong, callback
        completion(nil)

      }catch(let err) {

        // otherwise callback an error
        completion("\(err)")
      }//end do

    }//end dispatch
  }//end func

  /// delete an attribute to a DN
  /// - parameters:
  ///   - distinguishedName: specific DN
  ///   - attributes: attributes as an dictionary to delete
  /// - throws:
  ///   - Exception with message, such as no permission, or object class violation, etc.
  
  public func delete(distinguishedName: String) throws {

    // perform deletion
    let r = ldap_delete_ext_s(self.ldap, distinguishedName, nil, nil)

    guard r == 0 else {
      throw Exception.message(LDAP.error(r))
    }//end if
  }

  /// delete an attribute to a DN
  /// - parameters:
  ///   - distinguishedName: specific DN
  ///   - attributes: attributes as an dictionary to delete
  ///   - completion: callback once done. If something wrong, an error message will pass to the closure.
  
  public func delete(distinguishedName: String, completion: @escaping (String?)-> Void) {
    threading.async {
      do {
        // perform adding
        try self.delete(distinguishedName: distinguishedName)

        // if nothing wrong, callback
        completion(nil)

      }catch(let err) {

        // otherwise callback an error
        completion("\(err)")
      }//end do

    }//end dispatch
  }
}//end class
