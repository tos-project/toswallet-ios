//
//  NSDataExtensionTests.swift
//  TosWallet
//
//  Created by Samuel Sutch on 8/14/16.
//  Copyright © 2016 Aaron Voisine. All rights reserved.
//

import XCTest
@testable import breadwallet

class NSDataExtensionTests: XCTestCase {
    override func setUp() {
        super.setUp()
    }
    
    override func tearDown() {
        super.tearDown()
    }
    
    func testRoundTrip() {
        for _ in 0..<10 {
            let randomData = (1...7321).map{_ in UInt8(arc4random_uniform(0x30))}
            let data = Data(bytes: UnsafePointer<UInt8>(randomData), count: randomData.count)
            guard let compressed = data.bzCompressedData else {
                XCTFail("compressed data was nil")
                return
            }
            guard let decompressed = Data(bzCompressedData: compressed) else {
                XCTFail("decompressed data was nil")
                return
            }
            XCTAssertEqual(data.hexString, decompressed.hexString)
        }
    }
}
