import XCTest
@testable import AnisetteKit

final class LoginDiagnosticTraceTests: XCTestCase {
    func testErrorMetadataNeverIncludesProviderStrings() {
        let trace = LoginDiagnosticTrace()
        let privateValues = ["account@example.invalid", "TOKEN-CANARY", "PASSWORD-CANARY", "123456", "BLOB-CANARY"]
        let error = NSError(domain: privateValues.joined(), code: 42,
                            userInfo: [NSLocalizedDescriptionKey: privateValues.joined(),
                                       NSUnderlyingErrorKey: NSError(domain: "token", code: 7)])
        trace.begin(.appleAuthentication).finish(.failed, error: error)
        let snapshot = trace.snapshot(maximumBytes: 8192)
        for secret in privateValues { XCTAssertFalse(snapshot.contains(secret)) }
        XCTAssertTrue(snapshot.contains(",8,0"))
        XCTAssertFalse(snapshot.contains(",42"))
    }
    func testTerminalEventIsExactlyOnceAndDurationIsMonotonicBounded() {
        let trace = LoginDiagnosticTrace()
        let span = trace.begin(.nativeStart)
        span.finish(.succeeded)
        span.finish(.failed, error: AnisetteError.adiError(code: -45061, description: "TOKEN-CANARY"))
        let rows = trace.snapshot().split(separator: ";").dropFirst(4)
        XCTAssertEqual(rows.count, 2)
        XCTAssertTrue(rows.last!.hasPrefix("34,1,"))
        for row in rows {
            let fields = row.split(separator: ",").compactMap { Int($0) }
            XCTAssertEqual(fields.count, 7)
            XCTAssertTrue((0...86_400_000).contains(fields[3]))
            XCTAssertTrue((0...86_400_000).contains(fields[4]))
        }
    }
    func testBoundsRetainFinalFailureAndMarkLoss() {
        let trace = LoginDiagnosticTrace()
        for _ in 0..<300 { trace.begin(.twoFactorRequest).finish(.succeeded) }
        trace.begin(.nativeEnd).finish(.failed, error: AnisetteError.adiError(code: -45061, description: "SECRET"))
        let snapshot = trace.snapshot(maximumBytes: 256)
        XCTAssertLessThanOrEqual(snapshot.utf8.count, 256)
        XCTAssertEqual(snapshot.split(separator: ";")[3], "1")
        XCTAssertTrue(snapshot.contains(",2,-45061"))
        XCTAssertEqual(trace.snapshot(maximumBytes: 0), "")
        XCTAssertEqual(trace.snapshot(maximumBytes: 63), "")
    }
    func testNativeTimingIsStrictAndAtomic() {
        let trace = LoginDiagnosticTrace()
        let empty = trace.snapshot()
        for invalid in ["TOKEN-CANARY", "v1;0;0,2,0,0;TOKEN-CANARY", "v1;0;00,2,0,0",
                        "v1;0;15,1,0,0", "v1;0;1,4,0,0", "v1;0;0,1,-1,0",
                        "v1;0;0,1,0,86400001", "v1;0;0,1,0,0;", String(repeating: "x", count: 2056)] {
            trace.appendNativeTiming(invalid)
            XCTAssertEqual(trace.snapshot(), empty)
        }
        trace.appendNativeTiming("v1;0;3,0,0,0;3,2,12,12")
        let snapshot = trace.snapshot()
        XCTAssertTrue(snapshot.contains("55,0,0,"))
        XCTAssertTrue(snapshot.contains("55,2,4,"))
        XCTAssertTrue(snapshot.contains(",12,0,0"))
    }
    func testIndependentTaskLocalScopesDoNotBleed() async throws {
        let first = LoginDiagnosticTrace(), second = LoginDiagnosticTrace()
        XCTAssertNotEqual(first.correlationID, second.correlationID)
        await withTaskGroup(of: Void.self) { group in
            group.addTask {
                await LoginDiagnosticTrace.$current.withValue(first) {
                    await Task.yield()
                    LoginDiagnosticTrace.current?.begin(.nativeStart).finish(.succeeded)
                }
            }
            group.addTask {
                await LoginDiagnosticTrace.$current.withValue(second) {
                    await Task.yield()
                    LoginDiagnosticTrace.current?.begin(.twoFactorVerify).finish(.failed, reason: .cancelled)
                }
            }
        }
        XCTAssertTrue(first.snapshot().contains(";34,0,"))
        XCTAssertFalse(first.snapshot().contains(";21,0,"))
        XCTAssertTrue(second.snapshot().contains(";21,0,"))
        XCTAssertFalse(second.snapshot().contains(";34,0,"))
        XCTAssertNil(LoginDiagnosticTrace.current)
    }
    func testWrappersPreserveSuccessAndError() async throws {
        let value = try await withLoginDiagnosticStage(.appleLookup) { 42 }
        XCTAssertEqual(value, 42)
        do {
            _ = try await withLoginDiagnosticStage(.nativeOTP) { () async throws -> Int in
                throw AnisetteError.adiError(code: -45061, description: "ORIGINAL")
            }
            XCTFail("Expected original error")
        } catch {
            XCTAssertEqual(error as? AnisetteError, .adiError(code: -45061, description: "ORIGINAL"))
        }
    }
}
