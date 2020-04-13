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
        
        testBiometry()
        //testAccessGroup()
        //testCertificate()
        
    }

    func testBiometry() {
        
        //https://medium.com/@alx.gridnev/biometry-protected-entries-in-ios-keychain-6125e130e0d5
        
        let keychainManager = KeychainManager()
        //keychainManager.itemClass = .genericPassword
        
        let allValuesAndKeys = keychainManager.allValuesAndKeys()
        keychainManager.deleteAllValues()
        
        keychainManager.allowDebugValues = true
        
        var options = [UInt:AnyObject]()
        
        if #available(iOS 11.3, *) {
            options[KeychainValueOption.accessControlFlags.rawValue] = SecAccessControlCreateFlags.biometryCurrentSet as AnyObject
        }
        else {
            options[KeychainValueOption.accessControlFlags.rawValue] = SecAccessControlCreateFlags.devicePasscode as AnyObject
        }
        
        keychainManager.setStringValue(value: "111", for: "tmp_biometry", options: options)
        
        DispatchQueue.global(qos: .background).async {
            options[KeychainValueOption.useOperationPrompt.rawValue] = "Test b" as AnyObject
            let tmp = keychainManager.stringValue(for: "tmp_biometry", options: options)
            DispatchQueue.main.async {
                debugPrint(tmp ?? "nil")
            }
        }
        
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

}

