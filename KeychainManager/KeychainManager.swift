//  KeychainManager.swift
//  KeychainManager
//
//  Created by Andrey Evtyushin on 29/05/2019.
//  Copyright © 2019 Andrey Evtyushin. All rights reserved.
//

import Foundation

@objc(KeychainManager)
open class KeychainManager: NSObject {

    @objc public enum ItemClass: UInt {
        case genericPassword = 1
        case internetPassword = 2
    }
    
    @objc public class func shared() -> KeychainManager {
        struct __ {
            static let _shared = KeychainManager()
        }
        return __._shared
    }
    
    @objc public var itemClass: ItemClass = .internetPassword

    private var secClass: CFString {
        
        switch itemClass {
        case .genericPassword:
            return kSecClassGenericPassword
        case .internetPassword:
            return kSecClassInternetPassword
        }
        
    }
    
    private let secAttrAuthenticationType = kSecAttrAuthenticationTypeDefault
    private let secAttrProtocol = kSecAttrProtocolHTTPS
    private var secAttrAccessible: CFString {
        return kSecAttrAccessibleAlwaysThisDeviceOnly
    }

//    @objc public var server: String {
//
//        guard let bundleIdentifier = Bundle.main.bundleIdentifier else {
//            return "unknown"
//        }
//
//        return bundleIdentifier
//
//    }
    
    private var _server: String?
    @objc public var server: String {
        
        get {
            if _server == nil {
                if let bundleIdentifier = Bundle.main.bundleIdentifier {
                    _server = bundleIdentifier
                }
            }
            return _server ?? "default"
        }
        set {
            if _server != newValue {
                _server = newValue
            }
        }
        
    }
    
    private var _account: String?
    @objc public var account: String {
    
        get {
            if _account == nil {
                _account = getLastUsedAccount()
            }
            return _account ?? "default"
        }
        set {
            if _account != newValue {
                if setLastUsedAccount(newValue) {
                    _account = newValue
                }
            }
        }
        
    }
    
    @objc public var teamID: String?
    @objc public var accessGroup: String?
    
    @objc public var allowDebugAccounts = false
    @objc public var allowDebugValues = false
    @objc public var allowDebugCerificates = false
    
    @objc required public init(server: String? = nil, account: String? = nil) {
        
        super.init()
        
        if let server = server {
            self.server = server
        }
        
        if let account = account {
            self.account = account
        }
        
    }
    
}

//MARK: - Servers
extension KeychainManager {
    
    @objc public class func servers(debug: Bool = false) -> [String] {
        
        let query: Dictionary<String, AnyObject> = [
            String(kSecClass): kSecClassInternetPassword,
            String(kSecReturnAttributes): kCFBooleanTrue,
            String(kSecMatchLimit): kSecMatchLimitAll,
        ]
        
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        var servers = [String]()
        if status == errSecSuccess {
            if let items = result as? [[String: Any]] {
                for item in items {
                    if let server = item[String(kSecAttrServer)] as? String, !servers.contains(server) {
                        servers.append(server)
                    }
                }
            }
        }
        
        if debug {
            if status == errSecSuccess {
                debugPrint("[servers] get servers - '"+servers.joined(separator: ", ")+"'")
            }
            else {
                let error = KeychainError(code: status)
                let errorDescription = "("+String(error.code)+") "+error.description
                debugPrint("[servers] can't get servers, error = "+errorDescription)
            }
        }
        
        return servers
        
    }
    
}

//MARK: - Accounts
extension KeychainManager {
    
    private enum TechAccounts: String {
        case accounts = "accounts"
    }
    
    private var debugAccounts: Bool {
        
        #if DEBUG
        return allowDebugAccounts
        #else
        return false
        #endif
        
    }
    
    @objc public var techAccounts: [String]  {
        
        return [TechAccounts.accounts.rawValue]
        
    }
    
    @objc public var accounts: [String] {
        
        return getAccounts()
        
    }
    
    private var lastUsedAccount: String? {
        
        return getLastUsedAccount()
        
    }
    
    private var lastUsedAccountQuery: Dictionary<String, AnyObject> {
        
        let query: Dictionary<String, AnyObject> = [
            String(kSecClass): kSecClassInternetPassword,
            String(kSecAttrAccessible): kSecAttrAccessibleAlwaysThisDeviceOnly,
            String(kSecAttrServer): server as CFString,
            String(kSecAttrLabel): TechAccounts.accounts.rawValue as CFString,
        ]
        
        return query
        
    }
    
    private func getLastUsedAccount() -> String? {
        
        var query = lastUsedAccountQuery
        
        query[String(kSecReturnData)] = kCFBooleanTrue
        query[String(kSecMatchLimit)] = kSecMatchLimitOne
        
        var valueRef: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &valueRef)
        
        if status == errSecSuccess {
            if let valueRef = valueRef as? Data, let valueAsString = String(data: valueRef, encoding: .utf8) {
                return valueAsString
            }
        }
        
        return nil
        
    }
    
    @discardableResult func setLastUsedAccount(_ account: String) -> Bool {
        
        guard !isTechAccount(account) else {
            if debugAccounts {
                if isTechAccount(account) {
                    debugPrint("["+TechAccounts.accounts.rawValue+"] can't set last used account '"+account+"', error = is tech account")
                }
            }
            return false
        }
        
        let value = account.data(using: .utf8)
        
        var query = lastUsedAccountQuery
        
        if lastUsedAccountIsEmpty() {
            query[String(kSecValueData)] = value as AnyObject
            var persistentRef: CFTypeRef?
            let status = SecItemAdd(query as CFDictionary, &persistentRef)
            if debugAccounts {
                if status == errSecSuccess {
                    debugPrint("["+TechAccounts.accounts.rawValue+"] add last used account '"+account+"'")
                }
                else {
                    let error = KeychainError(code: status)
                    let errorDescription = "("+String(error.code)+") "+error.description
                    debugPrint("["+TechAccounts.accounts.rawValue+"] can't add last used account '"+account+"', error = "+errorDescription)
                }
            }
            return status == errSecSuccess
        }
        else {
            let attributesForUpdate: Dictionary<String, AnyObject> = [
                String(kSecValueData): value as AnyObject,
            ]
            let status = SecItemUpdate(query as CFDictionary, attributesForUpdate as CFDictionary)
            if debugAccounts {
                if status == errSecSuccess {
                    debugPrint("["+TechAccounts.accounts.rawValue+"] update last used account '"+account+"'")
                }
                else {
                    let error = KeychainError(code: status)
                    let errorDescription = "("+String(error.code)+") "+error.description
                    debugPrint("["+TechAccounts.accounts.rawValue+"] can't update last used account '"+account+"', error = "+errorDescription)
                }
            }
            return status == errSecSuccess
        }
        
    }
    
    private func lastUsedAccountIsEmpty() -> Bool {
        
        return getLastUsedAccount() == nil
        
    }
    
    private func getAccounts() -> [String] {
        
        var query: Dictionary<String, AnyObject> = [
            String(kSecClass): secClass,
            String(kSecAttrAccessible): secAttrAccessible,
            String(kSecReturnAttributes): kCFBooleanTrue,
            String(kSecMatchLimit): kSecMatchLimitAll,
        ]
        
        if itemClass == .internetPassword {
            query[String(kSecAttrProtocol)] = secAttrProtocol
            query[String(kSecAttrAuthenticationType)] = secAttrAuthenticationType
            query[String(kSecAttrServer)] = server as CFString
        }
        
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        var accounts = [String]()
        if status == errSecSuccess {
            if let items = result as? [[String: Any]] {
                for item in items {
                    if let account = item[String(kSecAttrAccount)] as? String, !isTechAccount(account) {
                        accounts.append(account)
                    }
                }
            }
        }
        
        if accounts.contains(account) {
            if let index = accounts.firstIndex(of: account) {
                accounts.remove(at: index)
                accounts.insert(account, at: 0)
            }
        }
        else {
            accounts.insert(account, at: 0)
        }
        
        if debugAccounts {
            if status == errSecSuccess {
                debugPrint("["+TechAccounts.accounts.rawValue+"] get accounts - '"+accounts.joined(separator: ", ")+"'")
            }
            else {
                let error = KeychainError(code: status)
                let errorDescription = "("+String(error.code)+") "+error.description
                debugPrint("["+TechAccounts.accounts.rawValue+"] can't get accounts, error = "+errorDescription)
            }
        }
        
        return accounts
        
    }
    
    private func isTechAccount(_ account: String) -> Bool {
        
        return techAccounts.contains(account)
        
    }
    
    private func accountIsExist(_ account: String) -> Bool {
        
        let accounts = getAccounts()
        return accounts.contains(account)
        
    }
    
}

//MARK: - Values
extension KeychainManager {
    
    @objc public enum KeychainValueOption: UInt {
        case server = 1
        case account = 2
        case accessGroup = 3
        case accessControlFlags = 4
        case synchronizable = 5
        case useOperationPrompt = 6
        case defaultValue = 99
    }
    
    private var debugValues: Bool {
        
        #if DEBUG
        return allowDebugValues
        #else
        return false
        #endif
        
    }
    
    private var secAttKey: CFString {
        
        switch itemClass {
        case .genericPassword:
            return kSecAttrService
        case .internetPassword:
            return kSecAttrPath////kSecAttrLabel
        }
        
    }
    
    private var defaultValueQuery: Dictionary<String, AnyObject> {
        
        var query: Dictionary<String, AnyObject> = [
            String(kSecClass): secClass,
            String(kSecAttrAccessible): secAttrAccessible,
            String(kSecAttrAccount): account as CFString,
        ]
        
        if var accessGroup = accessGroup {
            if let teamID = teamID {
                accessGroup = teamID+"."+accessGroup
            }
            query[String(kSecAttrAccessGroup)] = accessGroup as CFString
        }
        
        if itemClass == .internetPassword {
            query[String(kSecAttrProtocol)] = secAttrProtocol
            query[String(kSecAttrAuthenticationType)] = secAttrAuthenticationType
            query[String(kSecAttrServer)] = server as CFString
        }
        
        return query
        
    }
    
    private func valueIsExist(key: String, options: [UInt:AnyObject]? = nil) -> Bool {
        
        return dataValue(for: key, options: options) != nil
        
    }
    
    @objc public func boolValue(for key: String, options: [UInt:AnyObject]? = nil) -> Bool {
        
        if let value = stringValue(for: key, options: options) {
            return NSString(string: value).boolValue
        }
        else {
            if let options = options {
                if let defaultValue = options[KeychainValueOption.defaultValue.rawValue] as? Bool {
                    return defaultValue
                }
            }
            return false
        }
        
    }
    
    @objc public func dateValue(for key: String, options: [UInt:AnyObject]? = nil) -> Date? {
        
        if let value = stringValue(for: key, options: options) {
            let formatter = DateFormatter()
            formatter.dateFormat = "y-MM-dd H:m:ss.SSSS"
            return formatter.date(from: value)
        }
        else {
            if let options = options {
                if let defaultValue = options[KeychainValueOption.defaultValue.rawValue] as? Date {
                    return defaultValue
                }
            }
            return nil
        }
        
    }
    
    @objc public func stringValue(for key: String, options: [UInt:AnyObject]? = nil) -> String? {
        
        if let value = dataValue(for: key, options: options) {
            return String(data: value, encoding: .utf8)
        }
        else {
            if let options = options {
                if let defaultValue = options[KeychainValueOption.defaultValue.rawValue] as? String {
                    return defaultValue
                }
            }
            return nil
        }
        
    }
    
    @objc public func dataValue(for key: String, options: [UInt:AnyObject]? = nil) -> Data? {
        
        var query = defaultValueQuery
        query[String(secAttKey)] = key as CFString
        query[String(kSecReturnData)] = kCFBooleanTrue
        query[String(kSecMatchLimit)] = kSecMatchLimitOne
        
        //
        if let options = options {
            if var accessGroup = options[KeychainValueOption.accessGroup.rawValue] as? String, !accessGroup.isEmpty {
                if let teamID = teamID {
                    accessGroup = teamID+"."+accessGroup
                }
                query[String(kSecAttrAccessGroup)] = accessGroup as CFString
            }
            if let accessControlFlags = options[KeychainValueOption.accessControlFlags.rawValue] as? SecAccessControlCreateFlags {
                query.removeValue(forKey: String(kSecAttrAccessible))
                query[String(kSecAttrAccessControl)] = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                                                       secAttrAccessible,
                                                                                       accessControlFlags,
                                                                                       nil)!
            }
            if let operationPrompt = options[KeychainValueOption.useOperationPrompt.rawValue] as? String, !operationPrompt.isEmpty {
                query[String(kSecUseOperationPrompt)] = operationPrompt as CFString
            }
        }
        
        var valueRef: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &valueRef)
        
        if debugValues {
            if status == errSecSuccess {
                if let valueRef = valueRef as? Data, let valueAsString = String(data: valueRef, encoding: .utf8) {
                    debugPrint("["+account+"] get value for key '"+key+"' , value = '"+valueAsString+"'")
                }
                else {
                    debugPrint("["+account+"] get value for key '"+key+"'")
                }
            }
            else {
                let error = KeychainError(code: status)
                let errorDescription = "("+String(error.code)+") "+error.description
                debugPrint("["+account+"] can't get value for key '"+key+"' , error = "+errorDescription)
            }
        }
        
        if status == errSecSuccess, let valueRef = valueRef {
            return valueRef as? Data
        }
        else {
            if let options = options {
                if let defaultValue = options[KeychainValueOption.defaultValue.rawValue] as? Data {
                    return defaultValue
                }
            }
            return nil
        }
        
    }
    
    @objc public func setBoolValue(value: Bool, for key: String, options: [UInt:AnyObject]? = nil) {
        
        setStringValue(value: value.description, for: key, options: options)
        
    }
        
    @objc public func setDateValue(value: Date?, for key: String, options: [UInt:AnyObject]? = nil) {
        
        if let value = value {
            let formatter = DateFormatter()
            formatter.dateFormat = "y-MM-dd H:m:ss.SSSS"
            setStringValue(value: formatter.string(from: value), for: key)
        }
        else {
            setValue(value: nil, for: key, options: options)
        }
        
    }
    
    @objc public func setStringValue(value: String?, for key: String, options: [UInt:AnyObject]? = nil) {
        
        setValue(value: value?.data(using: .utf8), for: key, options: options)
        
    }
    
    @objc public func setValue(value: Data?, for key: String, options: [UInt:AnyObject]? = nil) {
        
        guard let value = value else {
            deleteValue(for: key)
            return
        }
        
        if valueIsExist(key: key, options: options) {
            updateValue(value: value, for: key)
        }
        else{
            addValue(value: value, for: key, options: options)
        }
        
    }
    
    private func addValue(value: Data, for key: String, options: [UInt:AnyObject]? = nil) {
        
        var query = defaultValueQuery
        
        query[String(secAttKey)] = key as CFString
        query[String(kSecValueData)] = value as AnyObject
        
        if let options = options {
            if var accessGroup = options[KeychainValueOption.accessGroup.rawValue] as? String, !accessGroup.isEmpty {
                if let teamID = teamID {
                    accessGroup = teamID+"."+accessGroup
                }
                query[String(kSecAttrAccessGroup)] = accessGroup as CFString
            }
            if let accessControlFlags = options[KeychainValueOption.accessControlFlags.rawValue] as? SecAccessControlCreateFlags {
                query.removeValue(forKey: String(kSecAttrAccessible))
                query[String(kSecAttrAccessControl)] = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                                                       secAttrAccessible,
                                                                                       accessControlFlags,
                                                                                       nil)!
            }
            if let synchronizable = options[KeychainValueOption.synchronizable.rawValue] as? Bool {
                query[String(kSecAttrSynchronizable)] = synchronizable as CFBoolean
            }
        }
        
        let status = SecItemAdd(query as CFDictionary, nil)
        
        if debugValues {
            if status == errSecSuccess {
                let valueAsString = String(data: value, encoding: .utf8) ?? ""
                debugPrint("["+account+"] add value for key '"+key+"' , value = '"+valueAsString+"'")
            }
            else {
                let error = KeychainError(code: status)
                let errorDescription = "("+String(error.code)+") "+error.description
                debugPrint("["+account+"] can't add value for key '"+key+"' , error = "+errorDescription)
            }
        }
        
    }
    
    private func updateValue(value: Data, for key: String, options: [UInt:AnyObject]? = nil) {
        
        var query = defaultValueQuery
        query[String(secAttKey)] = key as CFString
        
        var attributesForUpdate: Dictionary<String, AnyObject> = [
            String(kSecValueData): value as AnyObject,
        ]
        
        if let options = options {
            if var accessGroup = options[KeychainValueOption.accessGroup.rawValue] as? String, !accessGroup.isEmpty {
                if let teamID = teamID {
                    accessGroup = teamID+"."+accessGroup
                }
                attributesForUpdate[String(kSecAttrAccessGroup)] = accessGroup as CFString
            }
            if let accessControlFlags = options[KeychainValueOption.accessControlFlags.rawValue] as? SecAccessControlCreateFlags {
                attributesForUpdate.removeValue(forKey: String(kSecAttrAccessible))
                attributesForUpdate[String(kSecAttrAccessControl)] = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                                                       secAttrAccessible,
                                                                                       accessControlFlags,
                                                                                       nil)!
            }
            if let synchronizable = options[KeychainValueOption.synchronizable.rawValue] as? Bool {
                attributesForUpdate[String(kSecAttrSynchronizable)] = synchronizable as CFBoolean
            }
        }
        
        let status = SecItemUpdate(query as CFDictionary, attributesForUpdate as CFDictionary)
        
        if debugValues {
            if status == errSecSuccess {
                let valueAsString = String(data: value, encoding: .utf8) ?? ""
                debugPrint("["+account+"] update value for key '"+key+"' , value = '"+valueAsString+"'")
            }
            else {
                let error = KeychainError(code: status)
                let errorDescription = "("+String(error.code)+") "+error.description
                debugPrint("["+account+"] can't update value for key '"+key+"' , error = "+errorDescription)
            }
        }
        
    }
    
    @objc public func deleteValue(for key: String) {
        
        let query: Dictionary<String, AnyObject> = [
            String(kSecClass): secClass,
            String(kSecAttrAccount): account as CFString,
            String(secAttKey): key as CFString
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        
        if debugValues {
            if status == errSecSuccess {
                debugPrint("["+account+"] delete value for key '"+key+"'")
            }
            else {
                let error = KeychainError(code: status)
                let errorDescription = "("+String(error.code)+") "+error.description
                debugPrint("["+account+"] can't delete value for key '"+key+"' , error = "+errorDescription)
            }
        }
        
    }
    
    @objc public func allValuesAndKeys() -> [String:String] {
        
        var query = defaultValueQuery
        query[String(kSecReturnAttributes)] = kCFBooleanTrue
        query[String(kSecReturnData)] = kCFBooleanTrue
        query[String(kSecMatchLimit)] = kSecMatchLimitAll
        
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        var values = [String:String]()
        if status == errSecSuccess {
            if let items = result as? [[String: Any]] {
                for item in items {
                    if let key = item[String(secAttKey)] as? String,
                        let value = item[String(kSecValueData)] as? Data, let valueAsString = String(data: value, encoding: .utf8) {
                        values[key] = valueAsString
                    }
                }
            }
        }
        
        return values
        
    }
    
    @objc public func deleteAllValues() {
        
        var query: Dictionary<String, AnyObject> = [
            String(kSecClass): secClass,
            String(kSecAttrAccount): account as CFString,
        ]
        
        if itemClass == .internetPassword {
            query[String(kSecAttrServer)] = server as CFString
        }
        
        let status = SecItemDelete(query as CFDictionary)
        
        if debugValues {
            if status == errSecSuccess {
                debugPrint("["+account+"] delete all values")
            }
            else {
                let error = KeychainError(code: status)
                let errorDescription = "("+String(error.code)+") "+error.description
                debugPrint("["+account+"] can't delete all values , error = "+errorDescription)
            }
        }
        
    }
    
    @objc public class func deleteAll(debug: Bool = false) {
        
        let secClasses = [kSecClassInternetPassword,
                          kSecClassGenericPassword,
                          kSecClassCertificate,
                          kSecClassKey,
                          kSecClassIdentity]
        
        for secClass in secClasses {
            deleteAll(for: secClass, debug: debug)
        }
        
    }
    
    private class func deleteAll(for secClass: CFString, debug: Bool = false) {
        
        let query: Dictionary<String, AnyObject> = [
            String(kSecClass): secClass,
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        
        if debug {
            let secClassAsString = secClass as String
            if status == errSecSuccess {
                debugPrint("["+String(describing: self)+"] delete all values for secClass '"+secClassAsString+"'")
            }
            else {
                let error = KeychainError(code: status)
                let errorDescription = "("+String(error.code)+") "+error.description
                debugPrint("["+String(describing: self)+"] can't delete all values for secClass '"+secClassAsString+"', error = "+errorDescription)
            }
        }
        
    }
    
}

//MARK: - Certificates
extension KeychainManager {

    private var debugCertificate: Bool {

        #if DEBUG
            return allowDebugCerificates
        #else
            return false
        #endif

    }
    
    private var defaultSecIdentityQuery: Dictionary<String, AnyObject> {
        
        var query: Dictionary<String, AnyObject> = [
            String(kSecClass): kSecClassIdentity,
            //String(kSecAttrAccessible): secAttrAccessible,
            String(kSecAttrApplicationTag): account as CFString,
        ]
        
        if var accessGroup = accessGroup {
            if let teamID = teamID {
                accessGroup = teamID+"."+accessGroup
            }
            query[String(kSecAttrAccessGroup)] = accessGroup as CFString
        }
        
        if itemClass == .internetPassword {
            query[String(kSecAttrApplicationLabel)] = server as CFString
        }
        
        return query
        
    }

    private func isSecIdentityExist(options: [UInt:AnyObject]? = nil) -> Bool {
        return secIdentity(options: options) != nil
    }

    private func secIdentity(options: [UInt:AnyObject]? = nil) -> SecIdentity? {

        var query = defaultSecIdentityQuery
        query[String(kSecReturnRef)] = kCFBooleanTrue
        //query[String(kSecMatchLimit)] = kSecMatchLimitOne
        
        if let options = options {
            if var accessGroup = options[KeychainValueOption.accessGroup.rawValue] as? String, !accessGroup.isEmpty {
                if let teamID = teamID {
                    accessGroup = teamID+"."+accessGroup
                }
                query[String(kSecAttrAccessGroup)] = accessGroup as CFString
            }
        }

        var secIdentityRef: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &secIdentityRef)

        if debugCertificate {
            if status == errSecSuccess {
                debugPrint("["+account+"] get sec identity")
            }
            else {
                let error = KeychainError(code: status)
                let errorDescription = "("+String(error.code)+") "+error.description
                debugPrint("["+account+"] can't get sec identity , error = "+errorDescription)
            }
        }
                
        if status == errSecSuccess, secIdentityRef != nil {
            return (secIdentityRef as! SecIdentity)
        }
        else{
            return nil
        }

    }

//    private func persistentRefForSecIdentity() -> CFTypeRef? {
//
//        var query = defaultSecIdentityQuery
//        query[String(kSecReturnPersistentRef)] = kCFBooleanTrue
//        query[String(kSecMatchLimit)] = kSecMatchLimitOne
//
//        var persistentRef: CFTypeRef?
//        let status = SecItemCopyMatching(query as CFDictionary, &persistentRef)
//
//        if debugCertificate {
//            if status == errSecSuccess {
//                debugPrint("["+account+"] get persistent ref for sec identity")
//            }
//            else {
//                let error = KeychainError(code: status)
//                let errorDescription = "("+String(error.code)+") "+error.description
//                debugPrint("["+account+"] can't get persistent ref for sec identity , error = "+errorDescription)
//            }
//        }
//
//        return persistentRef
//
//    }

    private func addSecIdentity(secIdentity: SecIdentity, options: [UInt:AnyObject]? = nil) -> OSStatus {

        //https://stackoverflow.com/questions/11614047/what-makes-a-keychain-item-unique-in-ios
        //few Identities https://forums.developer.apple.com/thread/69642

//        var query: Dictionary<String, AnyObject> = [
//            //                String(kSecClass): kSecClassIdentity,
//            //                String(kSecAttrAccessible): secAttrAccessible,
//            //String(kSecAttrLabel): server as CFString,
//            String(kSecReturnPersistentRef): kCFBooleanTrue,
//            String(kSecValueRef): secIdentity ,
//        ]
        
        var query = defaultSecIdentityQuery
        query.removeValue(forKey: String(kSecClass))
        query[String(kSecReturnPersistentRef)] = kCFBooleanTrue
        query[String(kSecValueRef)] = secIdentity
        
        if let options = options {
            if var accessGroup = options[KeychainValueOption.accessGroup.rawValue] as? String, !accessGroup.isEmpty {
                if let teamID = teamID {
                    accessGroup = teamID+"."+accessGroup
                }
                query[String(kSecAttrAccessGroup)] = accessGroup as CFString
            }
        }
        
        var persistentRef: CFTypeRef?
        let status = SecItemAdd(query as CFDictionary, &persistentRef)

        if debugCertificate {
            if status == errSecSuccess {
                debugPrint("["+account+"] add sec identity")
            }
            else {
                let error = KeychainError(code: status)
                let errorDescription = "("+String(error.code)+") "+error.description
                debugPrint("["+account+"] can't add sec identity , error = "+errorDescription)
            }
        }
        
        return status

    }

    private func secIdentity(from data: Data, password: String, status: inout OSStatus) -> SecIdentity? {

        //About get SecIdentity from Data
        //https://forums.developer.apple.com/thread/68897
        //https://stackoverflow.com/questions/11173711/how-do-i-programmatically-import-a-certificate-into-my-ios-apps-keychain-and-pa

        var items: CFArray? = nil
        let options: Dictionary<String, AnyObject> = [
            String(kSecImportExportPassphrase): password as CFString,
        ]

        status = SecPKCS12Import(data as NSData, (options as CFDictionary), &items)

        if debugCertificate {
            if status == errSecSuccess {
                debugPrint("["+account+"] extract sec identity from data")
            }
            else {
                let error = KeychainError(code: status)
                let errorDescription = "("+String(error.code)+") "+error.description
                debugPrint("["+account+"] can't extarct sec identity from data , error = "+errorDescription)
            }
        }
        
        if status == errSecSuccess {
            let secIdentities = items as! [[String:Any]]
            if let secIdentity = secIdentities[0][kSecImportItemIdentity as String] {
                return (secIdentity as! SecIdentity)
            }
        }

        return nil

    }
    
    @objc public func allCertificates() -> [String:String] {
        
        var query = defaultSecIdentityQuery
        query[String(kSecReturnAttributes)] = kCFBooleanTrue
        query[String(kSecMatchLimit)] = kSecMatchLimitAll
        
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        var values = [String:String]()
        if status == errSecSuccess {
            if let items = result as? [[String: Any]] {
                for item in items {
                    
//                    if let key = item[String(secAttKey)] as? String,
//                        let value = item[String(kSecValueData)] as? Data, let valueAsString = String(data: value, encoding: .utf8) {
//                        values[key] = valueAsString
//                    }
                }
            }
        }
        
        return values
        
    }

    private func deleteSecIdentity() -> OSStatus {

//        let query: Dictionary<String, AnyObject> = [
//            String(kSecClass): kSecClassIdentity,
//            String(kSecAttrLabel): server as CFString,
//        ]
        
        let query = defaultSecIdentityQuery

        let status = SecItemDelete(query as CFDictionary)

        if debugCertificate {
            if status == errSecSuccess {
                debugPrint("["+account+"] delete sec identity")
            }
            else {
                let error = KeychainError(code: status)
                let errorDescription = "("+String(error.code)+") "+error.description
                debugPrint("["+account+"] can't delete sec identity , error = "+errorDescription)
            }
        }
        
        return status

    }

    func isCertificateInstalled(options: [UInt:AnyObject]? = nil) -> Bool {

        return isSecIdentityExist(options: options)

    }

    func certificateSecIdentity(options: [UInt:AnyObject]? = nil) -> SecIdentity? {

        return secIdentity(options: options)

    }

    @objc public func addCertificate(from data:Data, and password: String? = nil, options: [UInt:AnyObject]? = nil) -> Bool {

        var status: OSStatus = errSecSuccess
        if let secIdentity = secIdentity(from: data, password: password ?? "", status: &status) {
            if isSecIdentityExist(options: options) {
                status = deleteSecIdentity()
            }
            if status == errSecSuccess {
                status = addSecIdentity(secIdentity: secIdentity, options: options)
            }
        }

        if status == errSecSuccess {
            return true
        }
        else {
            return false
        }

    }

    @objc public func deleteCertificate() -> Bool {

        var status: OSStatus = errSecSuccess
        if isSecIdentityExist() {
            status = deleteSecIdentity()
        }

        if status == errSecSuccess {
            return true
        }
        else {
            return false
        }

    }

}

class KeychainError: LocalizedError {
    
    var code: OSStatus = noErr
    var description: String {
        
        if #available(iOS 11.3, *) {
            if let errorMessageString = SecCopyErrorMessageString(code, nil) as String? {
                return errorMessageString
            }
            else {
                return "Unknown error"
            }
        }
        else {
            return ""
        }
        
    }
    
    convenience init(code: OSStatus){
        self.init()
        self.code = code
    }
    
}
