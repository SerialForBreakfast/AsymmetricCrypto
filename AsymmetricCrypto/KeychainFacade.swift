//
//  KeychainFacade.swift
//  AsymmetricCrypto
//
//  Created by Joseph McCraw on 4/1/20.
//  Copyright © 2020 Joseph McCraw. All rights reserved.
//

import Foundation
import Security

enum KeychainFacadeError: Error {
    case keyGenerationError
    case failure(status: OSStatus)
    case noPublicKey
    case noPrivateKey
    case unsupported(algorithm: SecKeyAlgorithm)
    case unsupportedInput
    case forwarded(Error)
    case unknown
}

class KeychainFacade {
    // Set SHA-512 to default algorithm
    static var algorithm = SecKeyAlgorithm.rsaEncryptionOAEPSHA512
    
    lazy var privateKey: SecKey? = {
        guard let key = try? retrievePrivateKey(), key != nil else {
            return try? generatePrivateKey()
        }
        return key
    }()
    
    lazy var publicKey: SecKey? = {
        guard let key = privateKey else {
            return nil
        }
        return SecKeyCopyPublicKey(key)
    }()
    
    private static let tagData = "com.ShowBlender.AsymmetricCrypto.keys.mykey".data(using: String.Encoding.utf8)!
    
    private let keyAttributes: [String: Any] = [kSecAttrType as String: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits as String: 2048, kSecAttrApplicationTag as String: tagData, kSecPrivateKeyAttrs as String: [kSecAttrIsPermanent as String: true]]
    
    private func generatePrivateKey() throws -> SecKey {
        guard let privateKey = SecKeyCreateRandomKey(keyAttributes as CFDictionary, nil) else {
            throw KeychainFacadeError.keyGenerationError
        }
        return privateKey
    }
    
    private func retrievePrivateKey() throws -> SecKey? {
        let privateKeyQuery: [String: Any] = [kSecClass as String: kSecClassKey, kSecAttrApplicationTag as String: KeychainFacade.tagData, kSecAttrKeyType as String: kSecAttrKeyTypeRSA, kSecReturnRef as String: true]
        var privateKeyRef: CFTypeRef?
        let status = SecItemCopyMatching(privateKeyQuery as CFDictionary, &privateKeyRef)
        guard status == errSecSuccess else {
            if status == errSecItemNotFound {
                return nil
            } else {
                throw KeychainFacadeError.failure(status: status)
            }
        }
        return privateKeyRef != nil ? (privateKeyRef as! SecKey) : nil
    }
    
    func encrypt(text: String) throws -> Data? {
        guard let secKey = publicKey else {
            throw KeychainFacadeError.noPublicKey
        }
        
        guard SecKeyIsAlgorithmSupported(secKey, .encrypt, KeychainFacade.algorithm) else {
            throw KeychainFacadeError.unsupported(algorithm: KeychainFacade.algorithm)
        }
        guard let textData = text.data(using: .utf8) else {
            throw KeychainFacadeError.unsupportedInput
        }
        var error: Unmanaged<CFError>?
        guard let encryptedTextData = SecKeyCreateEncryptedData(secKey, KeychainFacade.algorithm, textData as CFData, &error) as Data? else {
            if let encryptionError = error {
                throw KeychainFacadeError.forwarded(encryptionError.takeRetainedValue() as Error)
            } else {
                throw KeychainFacadeError.unknown
            }
        }
        return encryptedTextData
    }
    
    func decrypt(data: Data) throws -> Data?{
        guard let secKey = privateKey else {
            throw KeychainFacadeError.noPrivateKey
        }
        guard SecKeyIsAlgorithmSupported(secKey, .decrypt, KeychainFacade.algorithm) else {
            throw KeychainFacadeError.unsupported(algorithm: KeychainFacade.algorithm)
        }
        var error: Unmanaged<CFError>?
        guard let decryptedData = SecKeyCreateDecryptedData(secKey, KeychainFacade.algorithm, data as CFData, &error) as Data? else {
            if let decryptionError = error {
                throw KeychainFacadeError.forwarded(decryptionError.takeRetainedValue() as Error)
                
            } else {
                throw KeychainFacadeError.unknown
            }
        }
        return decryptedData
    }
    
}
