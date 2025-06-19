//
//  HandshakeManager.swift
//
//
//  Created by zongbeen.han on 2025/06/17.
//

import iniNet

public class HandshakeManager {
    public init() {}
    
    public func initHandshake(ctx: NetContext, input: Data?) -> Result<Data, InisafeNetError> {
        var outputPtr: UnsafeMutablePointer<UInt8>? = nil
        var outputLen: Int32 = 0
        
        let inputResult = input?.withUnsafeBytes { (ptr: UnsafeRawBufferPointer) -> Int32 in
            INL_Handshake_Init(ctx.pointer(),
                               UnsafeMutablePointer(mutating: ptr.bindMemory(to: UInt8.self).baseAddress),
                               Int32(ptr.count),
                               &outputPtr,
                               &outputLen)
        } ?? INL_Handshake_Init(ctx.pointer(), nil, 0, &outputPtr, &outputLen)

        guard inputResult == 0, let output = outputPtr else {
            return .failure(.INISAFE_NET_HANDSHAKE_INIT_ERROR(inputResult))
        }
        
        let data = Data(bytesNoCopy: output, count: Int(outputLen), deallocator: .custom { ptr, _ in
            free(ptr)
        })
        
        return .success(data)
    }
    
    public func updateHandshake(ctx: NetContext, input: Data) -> Result<Data, InisafeNetError> {
        var outputPtr: UnsafeMutablePointer<UInt8>? = nil
        var outputLen: Int32 = 0
        
        let result = input.withUnsafeBytes { (ptr: UnsafeRawBufferPointer) in
            INL_Handshake_Update(ctx.pointer(),
                                 UnsafeMutablePointer(mutating: ptr.bindMemory(to: UInt8.self).baseAddress),
                                 Int32(ptr.count),
                                 &outputPtr,
                                 &outputLen)
        }
        
        guard result == 0, let output = outputPtr else {
            return .failure(.INISAFE_NET_HANDSHAKE_UPDATE_ERROR(result))
        }
        
        let data = Data(bytesNoCopy: output, count: Int(outputLen), deallocator: .custom { ptr, _ in
            free(ptr)
        })
        
        return .success(data)
    }
    
    public func finalizeHandshake(ctx: NetContext, input: Data) -> Result<Data, InisafeNetError> {
        var outputPtr: UnsafeMutablePointer<UInt8>? = nil
        var outputLen: Int32 = 0
        
        let result = input.withUnsafeBytes { (ptr: UnsafeRawBufferPointer) in
            INL_Handshake_Final(ctx.pointer(),
                                UnsafeMutablePointer(mutating: ptr.bindMemory(to: UInt8.self).baseAddress),
                                Int32(ptr.count),
                                &outputPtr,
                                &outputLen)
        }
        
        guard result == 0, let output = outputPtr else {
            return .failure(.INISAFE_NET_HANDSHAKE_FINAL_ERROR(result))
        }
        
        let data = Data(bytesNoCopy: output, count: Int(outputLen), deallocator: .custom { ptr, _ in
            free(ptr)
        })
        
        return .success(data)
    }
}
