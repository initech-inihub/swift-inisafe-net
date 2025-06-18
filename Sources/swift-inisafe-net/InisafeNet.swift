//
//  InisafeNet.swift
//
//
//  Created by zongbeen.han on 2025/06/17.
//

import iniNet

public class InisafeNet {
    public init() {}
    
    @discardableResult
    public func initialize(type: Int, configPath: String, licensePath: String) -> Int32 {
        return configPath.withCString { confCString in
            licensePath.withCString { licCString in
                INL_Initialize(Int32(type), UnsafeMutablePointer(mutating: confCString), UnsafeMutablePointer(mutating: licCString))
            }
        }
    }
    
    public func createNewCtx(type: Int32) -> UnsafeMutablePointer<net_ctx>? {
        var ctxPtr: UnsafeMutablePointer<net_ctx>? = nil

        let result = INL_New_Ctx(type, &ctxPtr)

        guard result == 0, let validCtx = ctxPtr else {
            return nil
        }

        return validCtx
    }
    
    @discardableResult
    public func setClientVersion(ctx: UnsafeMutablePointer<net_ctx>, version: String) -> Int32 {
        return version.withCString { cString in
            INL_SetClientVer(ctx, UnsafeMutablePointer(mutating: cString))
        }
    }
    
    public func freeBuffer(_ pointer: UnsafeMutablePointer<UInt8>?) {
        guard let ptr = pointer else { return }
        INL_Free_Buf(ptr)
    }

    
    @discardableResult
    public func freeCtx(_ ctx: UnsafeMutablePointer<net_ctx>?) -> Int32? {
        guard let ctx = ctx else {
            return nil
        }
        return INL_Free_Ctx(ctx)
    }
    
    public func encrypt(ctx: UnsafeMutablePointer<net_ctx>, plaintextPtr: UnsafeMutablePointer<UInt8>, plaintextLen: Int32) -> Data? {
        var ciphertextPtr: UnsafeMutablePointer<UInt8>? = nil
        var ciphertextLen: Int32 = 0

        let result = INL_Encrypt(ctx, plaintextPtr, plaintextLen, &ciphertextPtr, &ciphertextLen)

        guard result == 0, let ct = ciphertextPtr else {
            return nil
        }

        defer {
            INL_Free_Buf(ct)
        }

        return Data(bytes: ct, count: Int(ciphertextLen))
    }
    
    public func decrypt(ctx: UnsafeMutablePointer<net_ctx>, ciphertextPtr: UnsafeMutablePointer<UInt8>, ciphertextLen: Int32) -> Data? {
        var plaintextPtr: UnsafeMutablePointer<UInt8>? = nil
        var plaintextLen: Int32 = 0

        let result = INL_Decrypt(ctx, ciphertextPtr, ciphertextLen, &plaintextPtr, &plaintextLen)

        guard result == 0, let pt = plaintextPtr else {
            return nil
        }

        defer {
            INL_Free_Buf(pt)
        }

        return Data(bytes: pt, count: Int(plaintextLen))
    }
    
    public func handshakeManager() -> HandshakeManager {
        return HandshakeManager()
    }

//TODO: - KeyFix, KeyExchange
    /*
    public func keyFixManager() -> KeyFixManager {
        return KeyFixManager()
    }

    public func keyExchangeManager() -> KeyExchangeManager {
        return KeyExchangeManager()
    }
    */
}
