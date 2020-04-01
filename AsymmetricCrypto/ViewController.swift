//
//  ViewController.swift
//  AsymmetricCrypto
//
//  Created by Joseph McCraw on 4/1/20.
//  Copyright © 2020 Joseph McCraw. All rights reserved.
//

import UIKit

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
        testEncryptDecrypt()
    }

    private func testEncryptDecrypt() {
        let facade = KeychainFacade()
        let text = "Impossible to guess data."
        
        do {
            if let encryptedData = try facade.encrypt(text: text) {
                print("Text Encryption Successful")
                if let decryptedData = try facade.decrypt(data: encryptedData) {
                    print("Data decrypted successfully")
                    print("decrypted data: \(String(data: decryptedData, encoding: .utf8) ?? "")")
                }
            }
        } catch {
            print("error: \(error)")
        }
    }
}

