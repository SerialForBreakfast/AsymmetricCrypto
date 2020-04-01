//
//  AsymmetricCryptoTests.swift
//  AsymmetricCryptoTests
//
//  Created by Joseph McCraw on 4/1/20.
//  Copyright © 2020 Joseph McCraw. All rights reserved.
//

import XCTest
@testable import AsymmetricCrypto

class AsymmetricCryptoTests: XCTestCase {

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }
    
    func testEncryptDecrypt() throws {
        let facade = KeychainFacade()
        let text = "Impossible to guess data."
        
        do {
            if let encryptedData = try facade.encrypt(text: text) {
                if let decryptedData = try facade.decrypt(data: encryptedData) {
                    let decryptedText = String(data: decryptedData, encoding: .utf8) ?? ""
                    print("decrypted data: \(decryptedText)")
                    XCTAssert(text == decryptedText)
                }
            }
        } catch {
            print("error: \(error)")
        }
    }

}
