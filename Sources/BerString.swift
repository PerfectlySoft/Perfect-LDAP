//
//  BerString.swift
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

extension Iconv {

  /// directly convert a string from a berval structure
  /// - parametres:
  ///   - from: struct berval, pointer to transit
  /// - returns:
  ///   encoded string
  public func convert(from: berval) -> String {
    let (ptr, _) = self.convert(buf: from.bv_val, length: Int(from.bv_len))
    guard let p = ptr else {
      return ""
    }//end guard
    let str = String(validatingUTF8: p)
    p.deallocate(capacity: Int(from.bv_len) * 2)
    return str ?? ""
  }//end convert
}
