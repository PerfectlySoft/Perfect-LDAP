//
//  Utilities.swift
//  PerfectLDAP
//
//  Created by Rocky Wei on 2017-01-21.
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

import PerfectICONV
import OpenLDAP
/// C library of SASL
import SASL

extension Iconv {

  /// directly convert a string from a berval structure
  /// - parameters:
  ///   - from: struct berval, pointer to transit
  /// - returns:
  ///   encoded string
  public func convert(from: berval) -> String {
    let (ptr, _) = self.convert(buf: from.bv_val, length: Int(from.bv_len))
    guard let p = ptr else {
      return ""
    }//end guard
    let str = String(validatingUTF8: p)
    p.deallocate()
    return str ?? ""
  }//end convert
}

extension Array {

  /// generic function of converting array to a null terminated pointer array
  /// *CAUTION* memory MUST BE RELEASED MANUALLY
  /// - return:
  ///   a pointer array with each pointer is pointing the corresponding element, ending with a null pointer.
  public func asUnsafeNullTerminatedPointers() -> UnsafeMutablePointer<UnsafeMutablePointer<Element>?> {
    let pointers = UnsafeMutablePointer<UnsafeMutablePointer<Element>?>.allocate(capacity: self.count + 1)
    for i in 0 ..< self.count {
      let p =  UnsafeMutablePointer<Element>.allocate(capacity: 1)
      p.initialize(to: self[i])
      pointers.advanced(by: i).pointee = p
    }
    pointers.advanced(by: self.count).pointee = nil
    return pointers
  }//func
}//end array

public func withCArrayOfString<R>(array: [String] = [], _ body: (UnsafeMutablePointer<UnsafeMutablePointer<Int8>?>?) throws -> R) rethrows -> R {

  if array.isEmpty {
    return try body(nil)
  }//end if

  // duplicate the array and append a null string
  var attr: [String?] = array
  attr.append(nil)

  // duplicate again and turn it into an array of pointers
  var parr = attr.map { $0 == nil ? nil : ber_strdup($0!) }

  // perform the operation
  let r = try parr.withUnsafeMutableBufferPointer { try body ($0.baseAddress) }

  // release allocated string pointers.
  for p in parr { ber_memfree(UnsafeMutablePointer(mutating: p)) }

  return r
}//end withCArrayOfString








