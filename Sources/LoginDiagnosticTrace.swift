// Temporary, bounded login diagnostics. Remove with the investigation.
// Input is finite metadata only: no free-form messages, credentials or native dumps.
import Foundation
import Dispatch

public enum LoginDiagnosticStage: Int, CaseIterable, Sendable {
    case login, uiCredentials, preconditions, credentialRead, credentialRoute
    case anisetteFetch, keychainRead, pairValidation, blobPresence, requestHeaders
    case primaryProvider, freshBlobCommit, recovery, recoveryCurrentProbe, recoveryLegacyRead
    case recoveryLegacyProbe, recoveryCommit, appleAuthentication, twoFactor, twoFactorDelivery
    case twoFactorRequest, twoFactorVerify, credentialCommit, sessionCommit, accountSave
    case accountFinalize, cleanup, accountLookup, provisioning, clientInitialization
    case libraryValidation, provisioningBlob, appleLookup, appleSPIM, nativeStart
    case appleFinish, nativeEnd, nativeOTP, headerAssembly, authLookup
    case authSRPInit, authSRPChallenge, authSRPComplete, authDecrypt, authSession
    case nativeSetup, nativeVM, nativeLibraryLoad, nativeConstructors, nativePath
    case nativeIdentifier, nativeSymbol, nativeOutput, nativeCleanup, nativeCall
    case nativeLibraryInitialization, nativeRelocation
    // Append only: existing stage IDs remain stable for diagnostic consumers.
    case remoteDescriptor, remoteStart, remoteEnd, remoteHeaders
}
public enum LoginDiagnosticOutcome: Int, Sendable { case started, succeeded, failed, skipped }
public enum LoginDiagnosticReason: Int, Sendable {
    case none, notRequired, cancelled, unavailable, rejected, retry, completed
    case invalidResponse, cached, fresh, disabled, stateChanged
}

/// A trace has one random, non-identity correlation ID and a fixed event budget.
/// TaskLocal is available on the package's iOS 15/macOS 12 deployment baseline.
/// Detached tasks and IPC must propagate owned metadata explicitly, never credentials.
public final class LoginDiagnosticTrace: @unchecked Sendable {
    @TaskLocal public static var current: LoginDiagnosticTrace? = nil
    public static let maximumEvents = 128
    public static let maximumSnapshotBytes = 8192
    public let correlationID = String(UUID().uuidString.replacingOccurrences(of: "-", with: "").prefix(12)).lowercased()
    public static let buildMarker = "login_trace_v1"
    private let lock = NSLock()
    private let origin = DispatchTime.now().uptimeNanoseconds
    private var events: [String] = []
    private var truncated = false
    private var printedEvents = 0
    private var printedTruncation = false

    public init() {}
    public func begin(_ stage: LoginDiagnosticStage) -> LoginDiagnosticSpan {
        let time = DispatchTime.now().uptimeNanoseconds
        record(stage, .started, .none, startedAt: time, error: nil)
        return LoginDiagnosticSpan(trace: self, stage: stage, startedAt: time)
    }
    public func skip(_ stage: LoginDiagnosticStage, reason: LoginDiagnosticReason) {
        record(stage, .skipped, reason, startedAt: DispatchTime.now().uptimeNanoseconds, error: nil)
    }
    fileprivate func record(_ stage: LoginDiagnosticStage, _ outcome: LoginDiagnosticOutcome,
                            _ reason: LoginDiagnosticReason, startedAt: UInt64, error: Error?, nativeDuration: UInt64? = nil) {
        let now = DispatchTime.now().uptimeNanoseconds
        let elapsed = Self.milliseconds(now, since: origin)
        let duration = nativeDuration ?? Self.milliseconds(now, since: startedAt)
        let metadata = Self.errorMetadata(error)
        // Error domains/descriptions/userInfo never enter the diagnostic payload.
        let row = "\(stage.rawValue),\(outcome.rawValue),\(reason.rawValue),\(elapsed),\(duration),\(metadata.kind),\(metadata.code)"
        lock.lock()
        defer { lock.unlock() }
        if events.count == Self.maximumEvents {
            events.removeFirst()
            truncated = true
        }
        events.append(row)
        guard printedEvents < Self.maximumEvents else {
            if !printedTruncation {
                printedTruncation = true
                print("[LOGIN_TRACE] build=\(Self.buildMarker) id=\(correlationID) trace.truncated")
            }
            return
        }
        printedEvents += 1
        // One bounded line per event, without changing the existing verbose toggle.
        print("[LOGIN_TRACE] build=\(Self.buildMarker) id=\(correlationID) seq=\(printedEvents) stage=\(stage) outcome=\(outcome) reason=\(reason) elapsed_ms=\(elapsed) duration_ms=\(duration) error_kind=\(metadata.kind) error_code=\(metadata.code)")
    }
    // Imported after the synchronous native call returns. Arrival order is kept;
    // duration is measured by native steady_clock, never inferred from wall time.
    func appendNativeTiming(_ encoded: String?) {
        guard let encoded, encoded.utf8.count <= 2055,
              encoded.utf8.allSatisfy({ $0 < 128 }) else { return }
        let parts = encoded.split(separator: ";", omittingEmptySubsequences: false)
        guard parts.count >= 3, parts.count <= 66, parts[0] == "v1",
              parts[1] == "0" || parts[1] == "1" else { return }
        var decoded: [(Int, Int, UInt64)] = []
        for row in parts.dropFirst(2) {
            let fields = row.split(separator: ",", omittingEmptySubsequences: false)
            guard fields.count == 4 else { return }
            let values = fields.compactMap { Int($0) }
            guard values.count == 4,
                  zip(fields, values).allSatisfy({ String($0.1) == String($0.0) }),
                  (0...14).contains(values[0]), (0...3).contains(values[1]),
                  (0...86_400_000).contains(values[2]), (0...86_400_000).contains(values[3]) else { return }
            decoded.append((values[0], values[1], UInt64(values[3])))
        }
        let stages: [LoginDiagnosticStage] = [.nativeSetup, .nativeVM, .nativeLibraryLoad,
            .nativeLibraryInitialization, .nativePath, .nativeIdentifier, .nativeSymbol, .nativeOTP,
            .nativeOutput, .nativeCleanup, .nativeStart, .nativeEnd, .nativeRelocation,
            .nativeConstructors, .nativeCall]
        for (stage, outcome, duration) in decoded {
            let state: LoginDiagnosticOutcome = outcome == 0 ? .started : (outcome == 1 ? .succeeded : (outcome == 2 ? .failed : .skipped))
            record(stages[stage], state, outcome == 2 ? .rejected : (outcome == 3 ? .notRequired : .none),
                   startedAt: DispatchTime.now().uptimeNanoseconds, error: nil, nativeDuration: duration)
        }
        if parts[1] == "1" { lock.lock(); truncated = true; lock.unlock() }
    }
    private static func milliseconds(_ now: UInt64, since start: UInt64) -> UInt64 {
        min(now >= start ? (now - start) / 1_000_000 : 0, 86_400_000)
    }
    private static func errorMetadata(_ error: Error?) -> (kind: Int, code: Int) {
        guard let error else { return (0, 0) }
        if error is CancellationError { return (1, 0) }
        if let native = error as? AnisetteError {
            switch native {
            case .adiError(let code, _): return (2, Int(code))
            case .httpError(let status, _): return (3, max(-999_999, min(status, 999_999)))
            case .invalidArgument: return (4, 1)
            case .loaderFailed: return (4, 2)
            case .symbolMissing: return (4, 3)
            case .readFailure: return (4, 4)
            case .invalidResponse: return (4, 5)
            case .librariesNotFound: return (4, 6)
            }
        }
        let ns = error as NSError
        // Numeric codes only for known system domains. Unknown providers are opaque.
        if ns.domain == NSURLErrorDomain { return (5, max(-999_999, min(ns.code, 999_999))) }
        if ns.domain == NSCocoaErrorDomain { return (6, max(-999_999, min(ns.code, 999_999))) }
        if ns.domain == NSOSStatusErrorDomain { return (7, max(-999_999, min(ns.code, 999_999))) }
        return (8, 0)
    }
    /// Wire v1: build marker; generated ID; truncated bit; stage,outcome,reason,
    /// elapsed milliseconds,duration milliseconds,error kind,numeric error code.
    /// The consumer must validate every field before accepting a snapshot.
    public func snapshot(maximumBytes: Int = 2048) -> String {
        guard maximumBytes >= 64 else { return "" }
        let budget = min(maximumBytes, Self.maximumSnapshotBytes)
        lock.lock()
        var rows = events
        var lost = truncated
        lock.unlock()
        while true {
            let value = "v1;\(Self.buildMarker);\(correlationID);\(lost ? 1 : 0);" + rows.joined(separator: ";")
            if value.utf8.count <= budget { return value }
            guard !rows.isEmpty else { return "" }
            rows.removeFirst()
            lost = true
        }
    }
}

public final class LoginDiagnosticSpan: @unchecked Sendable {
    private let trace: LoginDiagnosticTrace
    private let stage: LoginDiagnosticStage
    private let startedAt: UInt64
    private let lock = NSLock()
    private var completed = false
    fileprivate init(trace: LoginDiagnosticTrace, stage: LoginDiagnosticStage, startedAt: UInt64) {
        self.trace = trace; self.stage = stage; self.startedAt = startedAt
    }
    /// Idempotent even when a completion callback and cancellation race.
    public func finish(_ outcome: LoginDiagnosticOutcome, reason: LoginDiagnosticReason = .none, error: Error? = nil) {
        lock.lock()
        guard !completed else { lock.unlock(); return }
        completed = true
        lock.unlock()
        trace.record(stage, outcome, reason, startedAt: startedAt, error: error)
    }
    deinit { finish(.failed, reason: .unavailable) }
}

// Internal wrappers preserve the exact return value/error and never retry.
func withLoginDiagnosticStage<T>(_ stage: LoginDiagnosticStage,
                                 operation: () async throws -> T) async rethrows -> T {
    let span = LoginDiagnosticTrace.current?.begin(stage)
    do {
        let value = try await operation()
        span?.finish(.succeeded)
        return value
    } catch {
        span?.finish(.failed, reason: error is CancellationError ? .cancelled : .rejected, error: error)
        throw error
    }
}
func withSynchronousLoginDiagnosticStage<T>(_ stage: LoginDiagnosticStage,
                                            operation: () throws -> T) rethrows -> T {
    let span = LoginDiagnosticTrace.current?.begin(stage)
    do {
        let value = try operation()
        span?.finish(.succeeded)
        return value
    } catch {
        span?.finish(.failed, reason: error is CancellationError ? .cancelled : .rejected, error: error)
        throw error
    }
}
