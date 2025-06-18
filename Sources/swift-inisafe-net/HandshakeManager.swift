//
//  HandshakeManager.swift
//
//
//  Created by zongbeen.han on 2025/06/17.
//



import iniNet

public class HandshakeManager {
    
    public init() {}
    
    public func initHandshake(ctx: UnsafeMutablePointer<net_ctx>?, inputPtr: UnsafeMutablePointer<UInt8>?, inputLen: Int32) -> Data? {
        let inputPtr = inputPtr
        var outputPtr: UnsafeMutablePointer<UInt8>? = nil
        var outputLen: Int32 = 0
        
        let result = INL_Handshake_Init(ctx, inputPtr, inputLen, &outputPtr, &outputLen)
        
        guard result == 0 , let output = outputPtr else {
            return nil
        }
        
        defer {
            free(output)
        }
        
        return Data(bytes: output, count: Int(outputLen))
    }
    
    public func updateHandshake(ctx: UnsafeMutablePointer<net_ctx>, inputPtr: UnsafeMutablePointer<UInt8>, inputLen: Int32) -> Data? {
        var outputPtr: UnsafeMutablePointer<UInt8>? = nil
        var outputLen: Int32 = 0

        let result = INL_Handshake_Update(ctx, inputPtr, inputLen, &outputPtr, &outputLen)

        guard result == 0, let output = outputPtr else {
            return nil
        }

        defer {
            free(output)
        }

        return Data(bytes: output, count: Int(outputLen))
    }
    
    public func finalizeHandshake(ctx: UnsafeMutablePointer<net_ctx>, inputPtr: UnsafeMutablePointer<UInt8>, inputLen: Int32) -> Data? {
        var outputPtr: UnsafeMutablePointer<UInt8>? = nil
        var outputLen: Int32 = 0

        let result = INL_Handshake_Final(ctx, inputPtr, inputLen, &outputPtr, &outputLen)

        guard result == 0, let output = outputPtr else {
            return nil
        }

        defer {
            free(output)
        }

        return Data(bytes: output, count: Int(outputLen))
    }
}
