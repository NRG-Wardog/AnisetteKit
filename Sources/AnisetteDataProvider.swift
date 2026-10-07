//
//  AnisetteDataProvider.swift
//  AnisetteKit
//
//  Created by Magesh K on 07/09/26.
//  Copyright © 2026 Magesh K. All rights reserved.
//

import Foundation
import anisette_core


public protocol AnisetteDataProvider: Sendable {
    var requiresLocalLibraries: Bool { get }
    func getAnisetteHeaders(libDir: String, provisioningDir: String, identifier: [UInt8], adiPb: [UInt8]) async throws -> AnisetteDataResponse
    func startProvision(libDir: String, provisioningDir: String, identifier: [UInt8], spim: [UInt8]) async throws -> (cpim: Data, session: UInt32)
    func endProvision(libDir: String, provisioningDir: String, identifier: [UInt8], session: UInt32, ptm: [UInt8], tk: [UInt8]) async throws -> Data
}

public typealias CStringPointer = UnsafeMutablePointer<CChar>

extension AnisetteDataProvider {
    func parseHeadersResponse(code: Int32, outPtr: CStringPointer?, providerName: String) throws -> AnisetteDataResponse {
        guard let ptr = outPtr else {
            throw AnisetteError.loaderFailed(reason: "\(providerName) loader returned nil (code: \(code))")
        }
        var dict = try parseJSONString(String(cString: ptr))
        let temporaryTrace = dict.removeValue(forKey: "v3_native_trace")
        if let err = dict["error"] {
            throw AnisetteError.adiError(code: code, description: err + TemporaryAnisetteNativeTrace.suffix(temporaryTrace))
        }
        return try AnisetteDataResponse(from: dict)
    }

    func parseStartProvisionResponse(code: Int32, outPtr: CStringPointer?, providerName: String) throws -> (cpim: Data, session: UInt32) {
        guard let ptr = outPtr else {
            throw AnisetteError.loaderFailed(reason: "\(providerName) loader returned nil (code: \(code))")
        }
        let jsonData = String(cString: ptr).data(using: .utf8)!
        guard let dict = try JSONSerialization.jsonObject(with: jsonData) as? [String: Any] else {
            throw AnisetteError.invalidResponse(reason: "Bad JSON from start_provision")
        }
        if let err = dict["error"] as? String {
            throw AnisetteError.adiError(code: code, description: err)
        }
        guard let cpimBase64 = dict["cpim_base64"] as? String,
              let cpim = Data(base64Encoded: cpimBase64),
              let session = (dict["session"] as? NSNumber)?.uint32Value else 
        {
            throw AnisetteError.invalidResponse(reason: "Missing/invalid cpim_base64 or session")
        }
        return (cpim, session)
    }

    func parseEndProvisionResponse(code: Int32, outPtr: CStringPointer?, providerName: String) throws -> Data {
        guard let ptr = outPtr else {
            throw AnisetteError.loaderFailed(reason: "\(providerName) loader returned nil (code: \(code))")
        }
        let dict = try parseJSONString(String(cString: ptr))
        if let err = dict["error"] {
            throw AnisetteError.adiError(code: code, description: err)
        }
        guard let adiPbBase64 = dict["adi_pb_base64"], let adiPb = Data(base64Encoded: adiPbBase64) else {
            throw AnisetteError.invalidResponse(reason: "Missing/invalid adi_pb_base64")
        }
        return adiPb
    }

    private func parseJSONString(_ s: String) throws -> [String: String] {
        let data = s.data(using: .utf8)!
        return (try JSONSerialization.jsonObject(with: data) as? [String: String]) ?? [:]
    }
}

public struct UnicornAnisetteDataProvider: AnisetteDataProvider {
    public var requiresLocalLibraries: Bool { true }

    public init() {}

    public func getAnisetteHeaders(libDir: String, provisioningDir: String, identifier: [UInt8], adiPb: [UInt8]) throws -> AnisetteDataResponse {
        var outPtr: CStringPointer? = nil
        let res = get_anisette_headers_uc(libDir, provisioningDir, identifier, adiPb, UInt32(adiPb.count), &outPtr)
        defer { if let p = outPtr { free_c_string(p) } }
        return try parseHeadersResponse(code: res, outPtr: outPtr, providerName: "Unicorn")
    }

    public func startProvision(libDir: String, provisioningDir: String, identifier: [UInt8], spim: [UInt8]) throws -> (cpim: Data, session: UInt32) {
        var outPtr: CStringPointer? = nil
        let res = start_provision_uc(libDir, provisioningDir, identifier, spim, UInt32(spim.count), &outPtr)
        defer { if let p = outPtr { free_c_string(p) } }
        return try parseStartProvisionResponse(code: res, outPtr: outPtr, providerName: "Unicorn")
    }

    public func endProvision(libDir: String, provisioningDir: String, identifier: [UInt8], session: UInt32, ptm: [UInt8], tk: [UInt8]) throws -> Data {
        var outPtr: CStringPointer? = nil
        let res = end_provision_uc(libDir, provisioningDir, identifier, session, ptm, UInt32(ptm.count), tk, UInt32(tk.count), &outPtr)
        defer { if let p = outPtr { free_c_string(p) } }
        return try parseEndProvisionResponse(code: res, outPtr: outPtr, providerName: "Unicorn")
    }
}

#if os(macOS)
public struct NativeAnisetteDataProvider: AnisetteDataProvider {
    public var requiresLocalLibraries: Bool { true }

    public init() {}

    public func getAnisetteHeaders(libDir: String, provisioningDir: String, identifier: [UInt8], adiPb: [UInt8]) throws -> AnisetteDataResponse {
        var outPtr: CStringPointer? = nil
        let res = get_anisette_headers_c(libDir, provisioningDir, identifier, adiPb, UInt32(adiPb.count), &outPtr)
        defer { if let p = outPtr { free_c_string(p) } }
        return try parseHeadersResponse(code: res, outPtr: outPtr, providerName: "Native")
    }

    public func startProvision(libDir: String, provisioningDir: String, identifier: [UInt8], spim: [UInt8]) throws -> (cpim: Data, session: UInt32) {
        var outPtr: CStringPointer? = nil
        let res = start_provision_c(libDir, provisioningDir, identifier, spim, UInt32(spim.count), &outPtr)
        defer { if let p = outPtr { free_c_string(p) } }
        return try parseStartProvisionResponse(code: res, outPtr: outPtr, providerName: "Native")
    }

    public func endProvision(libDir: String, provisioningDir: String, identifier: [UInt8], session: UInt32, ptm: [UInt8], tk: [UInt8]) throws -> Data {
        var outPtr: CStringPointer? = nil
        let res = end_provision_c(libDir, provisioningDir, identifier, session, ptm, UInt32(ptm.count), tk, UInt32(tk.count), &outPtr)
        defer { if let p = outPtr { free_c_string(p) } }
        return try parseEndProvisionResponse(code: res, outPtr: outPtr, providerName: "Native")
    }
}
#endif

// DEBUG/TEMPORARY: diagnostic metadata belongs to one response, never headers.
private enum TemporaryAnisetteNativeTrace {
    static let enabled = true
    static let allowed: Set<String> = ["arguments.ok", "arguments.failed", "root.ok", "root.failed", "uuid_dir.created", "uuid_dir.exists", "uuid_dir.failed", "file.open.ok", "file.open.failed", "file.stream.ok", "file.stream.failed", "file.write.ok", "file.write.failed", "file.flush.ok", "file.flush.failed", "file.flush.not_checked", "file.close.ok", "file.close.failed", "file.read_open.ok", "file.read_open.failed", "file.readback.ok", "file.readback.failed", "file.readback.not_checked", "file.read_close.ok", "file.read_close.failed", "file.rename.ok", "file.rename.failed", "vm.init.ok", "vm.init.failed", "vm.reused", "setup.begin", "setup.ok", "setup.failed", "library.load.ok", "library.load.failed", "library.cached", "library.init.ok", "library.init.failed", "provisioning_path.ok", "provisioning_path.failed", "provisioning_path.cached", "android_id.ok", "android_id.failed", "android_id.cached", "native.symbol.ok", "native.symbol.failed", "native.otp.ok", "native.otp.failed", "native.output.ok", "native.output.failed", "native.output.not_checked", "cleanup.ok", "cleanup.failed", "cleanup.not_needed", "cleanup.not_requested", "response.allocation.failed", "trace.truncated"]

    static func suffix(_ value: String?) -> String {
        guard enabled, let value, !value.isEmpty, value.utf8.count <= 1024,
              value.utf8.allSatisfy({ $0 < 128 }) else { return "" }
        let tokens = value.split(separator: ",", omittingEmptySubsequences: false)
        guard tokens.count <= 32,
              tokens.allSatisfy({ allowed.contains(String($0)) }) else { return "" }
        return " [DEBUG_TEMPORARY_NATIVE_TRACE:\(value)]"
    }
}

// V3_ISOLATED_ANISETTE_OTP_V1. Existing identity/blob only; no provisioning API.
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

public enum IsolatedAnisetteOTPProvider {
    /// provisioningDir must be a caller-owned temporary directory.
    /// The original UUID and blob are never persisted or replaced by this API.
    public static func getExistingHeaders(
        libDir: URL, provisioningDir: URL, identifier: UUID, existingBlob: Data,
        headers: AnisetteRequestHeaders? = nil
    ) async throws -> [String: String] {
        guard !existingBlob.isEmpty, existingBlob.count <= 1_048_576,
              libDir.isFileURL, provisioningDir.isFileURL else {
            throw AnisetteError.invalidArgument
        }
        try Task.checkCancellation()
        #if canImport(Darwin) || canImport(Glibc)
        // The upstream memory-storage cleanup removes its UUID directory.
        // Give it a private, exclusively-created subroot that this call owns.
        var pattern = Array(provisioningDir.appendingPathComponent("isolated-otp-XXXXXX").path.utf8CString)
        let ownedRoot = try pattern.withUnsafeMutableBufferPointer { buffer -> URL in
            guard let created = mkdtemp(buffer.baseAddress!) else {
                throw AnisetteError.adiError(code: -6, description: "Isolated OTP staging failed")
            }
            return URL(fileURLWithPath: String(cString: created), isDirectory: true)
        }
        var cleaned = false
        defer { if !cleaned { try? FileManager.default.removeItem(at: ownedRoot) } }
        let client = try AnisetteClient(provisioningDir: ownedRoot,
            provider: IsolatedExistingBlobProvider(), libraryDirectoryResolver: { libDir })
        let result = try await client.getAnisetteData(identifier: identifier,
            storage: .memory(existingBlob: existingBlob), headers: headers)
        do {
            try FileManager.default.removeItem(at: ownedRoot)
            cleaned = true
        } catch {
            throw AnisetteError.adiError(code: -6, description: "Isolated OTP cleanup failed")
        }
        try Task.checkCancellation()
        guard result.newBlob == nil else { throw AnisetteError.invalidArgument }
        return result.headers
        #else
        throw AnisetteError.invalidArgument
        #endif
    }
}

private struct IsolatedExistingBlobProvider: AnisetteDataProvider {
    var requiresLocalLibraries: Bool { true }

    func getAnisetteHeaders(libDir: String, provisioningDir: String,
                           identifier: [UInt8], adiPb: [UInt8]) throws -> AnisetteDataResponse {
        guard identifier.count == 16, !adiPb.isEmpty, adiPb.count <= 1_048_576 else {
            throw AnisetteError.invalidArgument
        }
        var outPtr: CStringPointer? = nil
        let code = get_anisette_headers_isolated_uc(libDir, provisioningDir,
            identifier, adiPb, UInt32(adiPb.count), &outPtr)
        defer { if let outPtr { free_c_string(outPtr) } }
        return try parseHeadersResponse(code: code, outPtr: outPtr, providerName: "Isolated OTP")
    }

    func startProvision(libDir: String, provisioningDir: String, identifier: [UInt8],
                        spim: [UInt8]) throws -> (cpim: Data, session: UInt32) {
        throw AnisetteError.invalidArgument
    }

    func endProvision(libDir: String, provisioningDir: String, identifier: [UInt8],
                      session: UInt32, ptm: [UInt8], tk: [UInt8]) throws -> Data {
        throw AnisetteError.invalidArgument
    }
}
