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
        
        testAccessGroup()
        
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
        
        debugPrint(tmp)
        
    }

}

