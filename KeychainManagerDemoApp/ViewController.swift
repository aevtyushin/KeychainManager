//
//  ViewController.swift
//  KeychainManagerdemoApp
//
//  Created by Андрей Евтюшин on 27/09/2019.
//  Copyright © 2019 -. All rights reserved.
//

import UIKit
import KeychainManager

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        
        //testForceDelete()
        //testDefaultValues()
        //testBiometry()
        //testAccessGroup()
        //testCertificate()
        testKeys()
        
    }

    func testDefaultValues() {
        
        let keychainManager = KeychainManager()
        keychainManager.deleteAllValues()
        
        var options = [UInt:AnyObject]()
        
        //options[KeychainValueOption.defaultValue.rawValue] = true as AnyObject
        let boolValue = keychainManager.boolValue(for: "test_bool", options: options)
        
        //options[KeychainValueOption.defaultValue.rawValue] = Date() as AnyObject
        let dateValue = keychainManager.dateValue(for: "test_date", options: options)
        
        //options[KeychainValueOption.defaultValue.rawValue] = "Test" as AnyObject
        let stringValue = keychainManager.stringValue(for: "test_string", options: options)
        
        //options[KeychainValueOption.defaultValue.rawValue] = "Test Data".data(using: .utf8) as AnyObject
        let dataValue = keychainManager.dataValue(for: "test_data", options: options)
        
    }
    
    func testForceDelete() {
        
        let keychainManager = KeychainManager()
        keychainManager.allowDebugValues = true
        
        var options = [UInt:AnyObject]()
        
        if #available(iOS 11.3, *) {
            options[KeychainValueOption.accessControlFlags.rawValue] = SecAccessControlCreateFlags.biometryCurrentSet as AnyObject
        }
        else {
            options[KeychainValueOption.accessControlFlags.rawValue] = SecAccessControlCreateFlags.devicePasscode as AnyObject
        }
        
        options[KeychainValueOption.forceDelete.rawValue] = true as AnyObject
        
        keychainManager.setStringValue(value: "111", for: "tmp_biometry", options: options)
        
        DispatchQueue.global(qos: .background).async {
            options[KeychainValueOption.useOperationPrompt.rawValue] = "Test b" as AnyObject
            let tmp = keychainManager.stringValue(for: "tmp_biometry", options: options)
            DispatchQueue.main.async {
                debugPrint(tmp ?? "nil")
            }
        }
        
    }
    
    func testBiometry() {
        
        //https://medium.com/@alx.gridnev/biometry-protected-entries-in-ios-keychain-6125e130e0d5
        
        let keychainManager1 = KeychainManager(server: "mail.ru", account: nil)
        keychainManager1.allowDebugValues = true
        
        let keychainManager2 = KeychainManager(server: "corp.mail.ru", account: nil)
        keychainManager2.allowDebugValues = true
        
        let allValuesAndKeys1 = keychainManager1.allValuesAndKeys()
        keychainManager1.deleteAllValues()
        
        let allValuesAndKeys2 = keychainManager2.allValuesAndKeys()
        keychainManager2.deleteAllValues()
        
        //keychainManager.allowDebugValues = true
        
        var options = [UInt:AnyObject]()
        
//        if #available(iOS 11.3, *) {
//            options[KeychainValueOption.accessControlFlags.rawValue] = SecAccessControlCreateFlags.biometryCurrentSet as AnyObject
//        }
//        else {
//            options[KeychainValueOption.accessControlFlags.rawValue] = SecAccessControlCreateFlags.devicePasscode as AnyObject
//        }
        options[KeychainValueOption.accessGroup.rawValue] = "2655J94PWC.com.keychainmanager.demoapp" as AnyObject
        options[KeychainValueOption.forceDelete.rawValue] = true as AnyObject
        
        
        keychainManager1.setStringValue(value: "111", for: "tmp_biometry", options: options)
        keychainManager2.setStringValue(value: "222", for: "tmp_biometry", options: options)
        
        let tmp1 = keychainManager1.stringValue(for: "tmp_biometry", options: options)
        debugPrint(tmp1 ?? "nil")
        let tmp2 = keychainManager2.stringValue(for: "tmp_biometry", options: options)
        debugPrint(tmp2 ?? "nil")
        
//        DispatchQueue.global(qos: .background).async {
//            options[KeychainValueOption.useOperationPrompt.rawValue] = "Test b" as AnyObject
//            let tmp = keychainManager.stringValue(for: "tmp_biometry", options: options)
//            DispatchQueue.main.async {
//                debugPrint(tmp ?? "nil")
//            }
//        }
        
    }

    func testAccessGroup() {
        
        let keychainManager = KeychainManager()
        
        let allValuesAndKeys = keychainManager.allValuesAndKeys()
        keychainManager.deleteAllValues()
        
        keychainManager.allowDebugValues = true
        
        var options = [UInt:AnyObject]()
        
        options[KeychainValueOption.accessGroup.rawValue] = "2655J94PWC.com.keychainmanager.demoapp" as AnyObject
        
        keychainManager.setStringValue(value: "111", for: "tmp", options: options)
        let tmp = keychainManager.stringValue(for: "tmp", options: options)
        
        debugPrint(tmp ?? "nil")
        
    }
    
    func testCertificate() {
        
        let keychainManager = KeychainManager()
        keychainManager.allowDebugCerificates = true
        
        KeychainManager.deleteAll(debug: true)
        
        //_ = keychainManager.allCertificates()
        
        guard let cert1FilePath = Bundle.main.url(forResource: "cert_corp_mail", withExtension: "pfx") else {
            debugPrint("can't get url for cert file")
            return
        }
        
        guard let dataCert1 = try? Data(contentsOf: cert1FilePath) else {
            debugPrint("can't get data from file - "+cert1FilePath.absoluteString)
            return
        }
        
        _ = keychainManager.certificateSecIdentity()
        
        let resultAdd1 = keychainManager.addCertificate(from: dataCert1, and: "bvleHqdo", options: nil)
        debugPrint("result add - "+resultAdd1.description)
        
        _ = keychainManager.certificateSecIdentity()
        
//        let resultDelete1 = keychainManager.deleteCertificate()
//        debugPrint("result delete - "+resultDelete1.description)
        
    }
    
    func testKeys() {
        
        //testKeysDifferentAccounts()
        
        
        
        return
        
        KeychainManager.deleteAll(debug: false)
        
        let keychainManager = KeychainManager(server: "test.", account: "user1")
        keychainManager.allowDebugKeys = true
        
        var options = [UInt:AnyObject]()
        options[KeychainValueOption.keyAlgorithm.rawValue] = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256 as AnyObject
        
        var message = "123456"
        var messageData = message.data(using: .utf8)!
        
        if !keychainManager.isPrivateKeyExist(options: options) {
            keychainManager.addPrivateKey(options: options)
        }
        
        guard let privateKey1 = keychainManager.privateKey(options: options) else {
            debugPrint("private key is empty")
            return
        }
        
        keychainManager.sign(data: messageData, privateKey: privateKey1, options: options,
                             completion: {(signature, error) in
                                
                                if let signature = signature {
                                    
                                    debugPrint("sign data \(message), signature is - \(signature.base64EncodedString())")
                                    
                                    guard let publicKey1 = keychainManager.publicKey(privateKey: privateKey1) else {
                                        debugPrint("publicKey key is empty")
                                        return
                                    }
                                    
//                                    message = "1234567"
//                                    messageData = message.data(using: .utf8)!
                                    
                                    keychainManager.verify(data: messageData, signature: signature, publicKey: publicKey1, options: options,
                                                           completion: {(result, error) in
                                                            
                                                            debugPrint("verify - \(result)")
                                                            
                                                           })
                                    
                                }
                                
                             })
        
    }
    
    private func testKeysDifferentAccounts() {
        
        KeychainManager.deleteAll(debug: false)
        
        var options = [UInt:AnyObject]()
        
        let keychainManager = KeychainManager(server: "test.com", account: "user1")
        keychainManager.allowDebugKeys = true
        
        if !keychainManager.isPrivateKeyExist(options: options) {
            keychainManager.addPrivateKey(options: options)
        }
        
        keychainManager.account = "user2"
        
        var privateKey2 = keychainManager.privateKey()
        
        keychainManager.account = "user1"
        
        var privateKey1 = keychainManager.privateKey()
        
        keychainManager.account = "user2"
        
        if !keychainManager.isPrivateKeyExist(options: options) {
            keychainManager.addPrivateKey(options: options)
        }
        
        privateKey2 = keychainManager.privateKey()
        
        keychainManager.account = "user1"
        
        privateKey1 = keychainManager.privateKey()
        
    }

}

