//
//  InisafeNet.swift
//
//
//  Created by zongbeen.han on 2025/06/17.
//

import iniNet

// MARK: - 에러 정의
public enum InisafeNetError: Error {
    case initializationFailed(Int32)
    case ctxCreationFailed(Int32)
    case encryptionFailed(Int32)
    case decryptionFailed(Int32)
    case invalidInput
}

// MARK: - net_ctx 래퍼
public final class NetContext {
    private let ctx: UnsafeMutablePointer<net_ctx>

    init(ctx: UnsafeMutablePointer<net_ctx>) {
        self.ctx = ctx
    }

    deinit {
        INL_Free_Ctx(ctx)
    }

    func pointer() -> UnsafeMutablePointer<net_ctx> {
        return ctx
    }
}

// MARK: - InisafeNet
public class InisafeNet {
    public init() {}

    public func initialize(type: Int32, configPath: String, licensePath: String) -> Result<Void, InisafeNetError> {
        let result = configPath.withCString { confCString in
            licensePath.withCString { licCString in
                INL_Initialize(type, UnsafeMutablePointer(mutating: confCString), UnsafeMutablePointer(mutating: licCString))
            }
        }

        return result == 0 ? .success(()) : .failure(.initializationFailed(result))
    }

    public func createContext(type: Int32) -> Result<NetContext, InisafeNetError> {
        var ctxPtr: UnsafeMutablePointer<net_ctx>? = nil
        let result = INL_New_Ctx(type, &ctxPtr)

        guard result == 0, let ctx = ctxPtr else {
            return .failure(.ctxCreationFailed(result))
        }

        return .success(NetContext(ctx: ctx))
    }

    public func setClientVersion(ctx: NetContext, version: String) -> Result<Void, InisafeNetError> {
        let result = version.withCString {
            INL_SetClientVer(ctx.pointer(), UnsafeMutablePointer(mutating: $0))
        }

        return result == 0 ? .success(()) : .failure(.invalidInput)
    }

    public func encrypt(ctx: NetContext, plaintext: Data) -> Result<Data, InisafeNetError> {
        var ciphertextPtr: UnsafeMutablePointer<UInt8>? = nil
        var ciphertextLen: Int32 = 0

        let result = plaintext.withUnsafeBytes { (ptr: UnsafeRawBufferPointer) in
            INL_Encrypt(ctx.pointer(),
                        UnsafeMutablePointer(mutating: ptr.bindMemory(to: UInt8.self).baseAddress),
                        Int32(plaintext.count),
                        &ciphertextPtr,
                        &ciphertextLen)
        }

        guard result == 0, let ct = ciphertextPtr else {
            return .failure(.encryptionFailed(result))
        }

        let data = Data(bytesNoCopy: ct, count: Int(ciphertextLen), deallocator: .custom { ptr, _ in
            INL_Free_Buf(ptr.assumingMemoryBound(to: UInt8.self))
        })

        return .success(data)
    }

    public func decrypt(ctx: NetContext, ciphertext: Data) -> Result<Data, InisafeNetError> {
        var plaintextPtr: UnsafeMutablePointer<UInt8>? = nil
        var plaintextLen: Int32 = 0

        let result = ciphertext.withUnsafeBytes { (ptr: UnsafeRawBufferPointer) in
            INL_Decrypt(ctx.pointer(),
                        UnsafeMutablePointer(mutating: ptr.bindMemory(to: UInt8.self).baseAddress),
                        Int32(ciphertext.count),
                        &plaintextPtr,
                        &plaintextLen)
        }

        guard result == 0, let pt = plaintextPtr else {
            return .failure(.decryptionFailed(result))
        }

        let data = Data(bytesNoCopy: pt, count: Int(plaintextLen), deallocator: .custom { ptr, _ in
            INL_Free_Buf(ptr.assumingMemoryBound(to: UInt8.self))
        })

        return .success(data)
    }
}
