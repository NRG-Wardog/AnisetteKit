import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import anisette_core

/// One native transaction, including fresh provisioning, in a new VM and an
/// exclusively owned scratch directory. Cancellation is cooperative: fetch does
/// not return until the native worker has drained and cleanup has completed.
/// A caller's watchdog may show cleanupPending, but must not advance providers.
public final class OwnedOnDeviceAnisetteAttempt: @unchecked Sendable {
    private let provider: OwnedUnicornProvider
    private let client: AnisetteClient
    private let session: URLSession
    private let identifier: UUID
    private let lock = NSLock()
    private var started = false

    public convenience init(libraryDirectory: URL, verifiedLibraries: [String: Data], scratchParent: URL, identifier: UUID,
                budgetMilliseconds: UInt32 = 60_000) async throws {
        try await self.init(libraryDirectory: libraryDirectory, verifiedLibraries: verifiedLibraries,
            scratchParent: scratchParent, identifier: identifier, budgetMilliseconds: budgetMilliseconds,
            transportConfiguration: .ephemeral)
    }

    // Internal URLProtocol fixture seam. The attempt still constructs and owns
    // its session; no borrowed session or ambient/global transport is admitted.
    init(libraryDirectory: URL, verifiedLibraries: [String: Data], scratchParent: URL, identifier: UUID,
         budgetMilliseconds: UInt32 = 60_000, transportConfiguration: URLSessionConfiguration) async throws {
        guard libraryDirectory.isFileURL, scratchParent.isFileURL,
              budgetMilliseconds > 0, budgetMilliseconds <= 120_000 else { throw AnisetteError.invalidArgument }
        let library = libraryDirectory.resolvingSymlinksInPath().standardizedFileURL
        let parent = scratchParent.resolvingSymlinksInPath().standardizedFileURL
        let token = try await OwnedNativeHandle.create(library: library, parent: parent,
                                                       identifier: identifier, budget: budgetMilliseconds, libraries: verifiedLibraries)
        let provider = OwnedUnicornProvider(token: token, library: token.library, identifier: identifier)
        let configuration = transportConfiguration.copy() as! URLSessionConfiguration
        configuration.urlCache = nil
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.timeoutIntervalForRequest = 30
        configuration.timeoutIntervalForResource = 60
        let session = URLSession(configuration: configuration)
        do {
            self.client = try AnisetteClient(provisioningDir: token.directory, provider: provider,
                                            libraryDirectoryResolver: { token.library }, networkSession: session, allowsDiskStorage: false)
        } catch {
            session.invalidateAndCancel()
            _ = await provider.finish()
            throw error
        }
        self.provider = provider; self.session = session; self.identifier = identifier
    }

    public func cancel() { provider.cancel(); session.invalidateAndCancel() }

    public func fetch(existingBlob: Data?, headers: AnisetteRequestHeaders? = nil) async throws
        -> (headers: [String: String], newBlob: Data?) {
        let admitted = lock.withLock { () -> Bool in
            guard !started else { return false }
            started = true; return true
        }
        guard admitted else { throw AnisetteError.invalidArgument }
        return try await withTaskCancellationHandler {
            do {
                try Task.checkCancellation()
                let result = try await client.getAnisetteData(identifier: identifier,
                    storage: .memory(existingBlob: existingBlob), headers: headers)
                try Task.checkCancellation()
                let cleaned = await provider.finish()
                session.invalidateAndCancel()
                guard cleaned else { throw AnisetteError.adiError(code: -6, description: "Owned native cleanup failed") }
                try Task.checkCancellation()
                return result
            } catch {
                cancel()
                let cleaned = await provider.finish()
                guard cleaned else { throw AnisetteError.adiError(code: -6, description: "Owned native cleanup failed") }
                throw error
            }
        } onCancel: { self.cancel() }
    }

    deinit { session.invalidateAndCancel(); provider.cancel() }
}

// The worker closure strongly retains this handle. The C object cannot be freed
// by cancellation or an abandoned await while a native call still owns it.
private final class OwnedNativeHandle: @unchecked Sendable {
    let pointer: OpaquePointer
    let directory: URL
    let library: URL
    init(pointer: OpaquePointer, directory: URL, library: URL) { self.pointer = pointer; self.directory = directory; self.library = library }
    deinit { anisette_owned_attempt_release(pointer) }
    static func create(library: URL, parent: URL, identifier: UUID, budget: UInt32, libraries: [String: Data]) async throws -> OwnedNativeHandle {
        guard Set(libraries.keys) == Set(["libstoreservicescore.so", "libCoreADI.so"]),
              let ssc = libraries["libstoreservicescore.so"], let adi = libraries["libCoreADI.so"],
              !ssc.isEmpty, !adi.isEmpty, ssc.count <= 64 * 1_048_576, adi.count <= 64 * 1_048_576 else {
            throw AnisetteError.invalidArgument
        }
        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                let bytes = identifier.uuidBytes
                let pointer = bytes.withUnsafeBufferPointer {
                    anisette_owned_attempt_create(library.path, parent.path, $0.baseAddress, budget)
                }
                guard let pointer, let directory = anisette_owned_attempt_directory(pointer) else {
                    if let pointer { anisette_owned_attempt_release(pointer) }
                    continuation.resume(throwing: AnisetteError.adiError(code: -2, description: "Owned native attempt initialization failed"))
                    return
                }
                let staged = ssc.withUnsafeBytes { first in adi.withUnsafeBytes { second in
                    anisette_owned_attempt_stage_libraries(pointer, first.bindMemory(to: UInt8.self).baseAddress, UInt32(ssc.count),
                        second.bindMemory(to: UInt8.self).baseAddress, UInt32(adi.count))
                } }
                guard staged == 0, let privateLibrary = anisette_owned_attempt_library_directory(pointer) else {
                    anisette_owned_attempt_release(pointer)
                    continuation.resume(throwing: AnisetteError.adiError(code: -2, description: "Owned library staging failed")); return
                }
                continuation.resume(returning: OwnedNativeHandle(pointer: pointer,
                    directory: URL(fileURLWithPath: String(cString: directory), isDirectory: true),
                    library: URL(fileURLWithPath: String(cString: privateLibrary), isDirectory: true)))
            }
        }
    }
}

private final class OwnedUnicornProvider: AnisetteDataProvider, @unchecked Sendable {
    let requiresLocalLibraries = true
    private let token: OwnedNativeHandle
    private let library: URL
    private let identifier: UUID
    private let queue = DispatchQueue(label: "AnisetteKit.owned-native-attempt", qos: .userInitiated)
    init(token: OwnedNativeHandle, library: URL, identifier: UUID) {
        self.token = token; self.library = library; self.identifier = identifier
    }
    func cancel() { anisette_owned_attempt_cancel(token.pointer) }
    func finish() async -> Bool {
        await withCheckedContinuation { continuation in
            queue.async { [self] in
                let result = anisette_owned_attempt_finish(token.pointer)
                continuation.resume(returning: result == 0 && anisette_owned_attempt_is_quiescent(token.pointer) != 0)
            }
        }
    }
    private func validate(libDir: String, provisioningDir: String, identifier bytes: [UInt8]) throws {
        guard bytes == identifier.uuidBytes,
              URL(fileURLWithPath: libDir).resolvingSymlinksInPath().standardizedFileURL == library,
              URL(fileURLWithPath: provisioningDir).resolvingSymlinksInPath().standardizedFileURL == token.directory.resolvingSymlinksInPath().standardizedFileURL else {
            throw AnisetteError.invalidArgument
        }
    }
    private enum Operation: Sendable { case headers(Data), start(Data), end(UInt32, Data, Data) }
    private func invoke(_ operation: Operation) async throws -> (Int32, String) {
        try Task.checkCancellation()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                queue.async { [self] in
                    var output: UnsafeMutablePointer<CChar>?
                    let result: Int32
                    switch operation {
                    case .headers(let blob):
                        result = blob.withUnsafeBytes { anisette_owned_attempt_headers(token.pointer, $0.bindMemory(to: UInt8.self).baseAddress, UInt32(blob.count), &output) }
                    case .start(let spim):
                        result = spim.withUnsafeBytes { anisette_owned_attempt_start(token.pointer, $0.bindMemory(to: UInt8.self).baseAddress, UInt32(spim.count), &output) }
                    case .end(let session, let ptm, let tk):
                        result = ptm.withUnsafeBytes { first in tk.withUnsafeBytes { second in
                            anisette_owned_attempt_end(token.pointer, session, first.bindMemory(to: UInt8.self).baseAddress, UInt32(ptm.count), second.bindMemory(to: UInt8.self).baseAddress, UInt32(tk.count), &output)
                        } }
                    }
                    defer { if let output { free_c_string(output) } }
                    guard result == 0, let output else {
                        continuation.resume(throwing: AnisetteError.adiError(code: result, description: "Owned native operation stopped")); return
                    }
                    continuation.resume(returning: (result, String(cString: output)))
                }
            }
        } onCancel: { self.cancel() }
    }
    private func input(_ bytes: [UInt8]) throws -> Data {
        guard !bytes.isEmpty, bytes.count <= 1_048_576 else { throw AnisetteError.invalidArgument }
        return Data(bytes)
    }
    func getAnisetteHeaders(libDir: String, provisioningDir: String, identifier: [UInt8], adiPb: [UInt8]) async throws -> AnisetteDataResponse {
        try validate(libDir: libDir, provisioningDir: provisioningDir, identifier: identifier)
        let (code, json) = try await invoke(.headers(input(adiPb)))
        try Task.checkCancellation()
        return try json.withCString { try parseHeadersResponse(code: code, outPtr: UnsafeMutablePointer(mutating: $0), providerName: "Owned Unicorn") }
    }
    func startProvision(libDir: String, provisioningDir: String, identifier: [UInt8], spim: [UInt8]) async throws -> (cpim: Data, session: UInt32) {
        try validate(libDir: libDir, provisioningDir: provisioningDir, identifier: identifier)
        let (code, json) = try await invoke(.start(input(spim)))
        try Task.checkCancellation()
        return try json.withCString { try parseStartProvisionResponse(code: code, outPtr: UnsafeMutablePointer(mutating: $0), providerName: "Owned Unicorn") }
    }
    func endProvision(libDir: String, provisioningDir: String, identifier: [UInt8], session: UInt32, ptm: [UInt8], tk: [UInt8]) async throws -> Data {
        try validate(libDir: libDir, provisioningDir: provisioningDir, identifier: identifier)
        let (code, json) = try await invoke(.end(session, input(ptm), input(tk)))
        try Task.checkCancellation()
        return try json.withCString { try parseEndProvisionResponse(code: code, outPtr: UnsafeMutablePointer(mutating: $0), providerName: "Owned Unicorn") }
    }
}
