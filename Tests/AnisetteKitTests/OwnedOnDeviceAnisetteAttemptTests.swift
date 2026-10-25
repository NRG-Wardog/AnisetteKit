import Foundation
import XCTest
@testable import AnisetteKit

final class OwnedOnDeviceAnisetteAttemptTests: XCTestCase, @unchecked Sendable {
    // These synthetic bytes are staged but never executed: every fetch is
    // cancelled before native entry. Real engine procedures have a separate test.
    private let libraries = ["libstoreservicescore.so": Data([1,2,3]), "libCoreADI.so": Data([4,5,6])]
    private func root() throws -> URL {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
                                                 attributes: [.posixPermissions: 0o700])
        return root
    }
    private func children(_ root: URL) throws -> [String] {
        try FileManager.default.contentsOfDirectory(atPath: root.path)
    }
    func testCancelAfterInitializationBeforeFetchDrainsAndCleans() async throws {
        let parent = try root(); defer { try? FileManager.default.removeItem(at: parent) }
        let attempt = try await OwnedOnDeviceAnisetteAttempt(libraryDirectory: parent,
            verifiedLibraries: libraries, scratchParent: parent, identifier: UUID())
        XCTAssertEqual(try children(parent).count, 1)
        attempt.cancel()
        do { _ = try await attempt.fetch(existingBlob: Data([1])); XCTFail("Cancelled attempt returned headers") }
        catch { /* Expected cancellation/native rejection, after cleanup. */ }
        XCTAssertEqual(try children(parent), [])
        do { _ = try await attempt.fetch(existingBlob: Data([1])); XCTFail("Attempt admitted twice") }
        catch { }
        XCTAssertEqual(try children(parent), [])
    }
    func testAlreadyCancelledTaskStillDrainsInitializedAttempt() async throws {
        let parent = try root(); defer { try? FileManager.default.removeItem(at: parent) }
        let attempt = try await OwnedOnDeviceAnisetteAttempt(libraryDirectory: parent,
            verifiedLibraries: libraries, scratchParent: parent, identifier: UUID())
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await attempt.fetch(existingBlob: nil)
        }
        do { _ = try await task.value; XCTFail("Cancelled task returned headers") }
        catch { XCTAssertTrue(error is CancellationError) }
        XCTAssertEqual(try children(parent), [])
    }
    func testInvalidSnapshotCannotCreateAttemptRoot() async throws {
        let parent = try root(); defer { try? FileManager.default.removeItem(at: parent) }
        do {
            _ = try await OwnedOnDeviceAnisetteAttempt(libraryDirectory: parent,
                verifiedLibraries: ["../libCoreADI.so": Data([1])], scratchParent: parent, identifier: UUID())
            XCTFail("Unrecognized library snapshot admitted")
        } catch { }
        XCTAssertEqual(try children(parent), [])
    }
    func testAbandonedInitializedAttemptCleansOwnedRootOnly() async throws {
        let parent = try root(); defer { try? FileManager.default.removeItem(at: parent) }
        let sentinel = parent.appendingPathComponent("unrelated")
        try Data([42]).write(to: sentinel)
        var attempt: OwnedOnDeviceAnisetteAttempt? = try await OwnedOnDeviceAnisetteAttempt(libraryDirectory: parent,
            verifiedLibraries: libraries, scratchParent: parent, identifier: UUID())
        XCTAssertNotNil(attempt)
        attempt = nil
        XCTAssertEqual(try children(parent), ["unrelated"])
        XCTAssertEqual(try Data(contentsOf: sentinel), Data([42]))
    }
    func testFreshProvisioningLookupFailureDrainsWithoutNativeEntry() async throws {
        let parent = try root(); defer { try? FileManager.default.removeItem(at: parent) }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [OwnedLookupFixture.self]
        OwnedLookupFixture.configure(stall: false, started: nil)
        let attempt = try await OwnedOnDeviceAnisetteAttempt(libraryDirectory: parent,
            verifiedLibraries: libraries, scratchParent: parent, identifier: UUID(), transportConfiguration: configuration)
        do { _ = try await attempt.fetch(existingBlob: nil); XCTFail("Failed lookup returned headers") }
        catch { }
        XCTAssertEqual(OwnedLookupFixture.requestCount, 1)
        XCTAssertEqual(try children(parent), [])
    }
    func testFreshProvisioningCancellationWaitsForSessionAndNativeDrain() async throws {
        let parent = try root(); defer { try? FileManager.default.removeItem(at: parent) }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [OwnedLookupFixture.self]
        let entered = expectation(description: "owned provisioning lookup entered fixture")
        OwnedLookupFixture.configure(stall: true, started: entered)
        let attempt = try await OwnedOnDeviceAnisetteAttempt(libraryDirectory: parent,
            verifiedLibraries: libraries, scratchParent: parent, identifier: UUID(), transportConfiguration: configuration)
        let operation = Task { try await attempt.fetch(existingBlob: nil) }
        await fulfillment(of: [entered], timeout: 5)
        operation.cancel()
        do { _ = try await operation.value; XCTFail("Cancelled provisioning returned headers") }
        catch { }
        XCTAssertEqual(OwnedLookupFixture.requestCount, 1)
        XCTAssertEqual(try children(parent), [])
        OwnedLookupFixture.configure(stall: false, started: nil)
    }
    func testMemoryOnlyClientNeverReadsOrDeletesExistingDiskState() async throws {
        let parent = try root(); defer { try? FileManager.default.removeItem(at: parent) }
        let id = UUID()
        let child = parent.appendingPathComponent(id.uuidString.lowercased())
        try FileManager.default.createDirectory(at: child, withIntermediateDirectories: false)
        let sentinel = child.appendingPathComponent(AnisetteConstants.Files.rinfo)
        try "DISK-ROUTING-CANARY".write(to: sentinel, atomically: false, encoding: .utf8)
        let client = try AnisetteClient(provisioningDir: parent, provider: MemoryFixtureProvider(), allowsDiskStorage: false)
        let result = try await client.getAnisetteData(identifier: id, storage: .memory(existingBlob: Data([1])))
        XCTAssertFalse(result.headers.values.contains("DISK-ROUTING-CANARY"))
        XCTAssertEqual(try String(contentsOf: sentinel, encoding: .utf8), "DISK-ROUTING-CANARY")
        do { _ = try await client.getAnisetteData(identifier: id, storage: .disk); XCTFail("Disk storage admitted") }
        catch { }
        XCTAssertTrue(FileManager.default.fileExists(atPath: sentinel.path))
    }

}

private struct MemoryFixtureProvider: AnisetteDataProvider {
    let requiresLocalLibraries = false
    func getAnisetteHeaders(libDir: String, provisioningDir: String, identifier: [UInt8], adiPb: [UInt8]) async throws -> AnisetteDataResponse {
        AnisetteDataResponse(oneTimePassword: "SYNTHETIC-OTP", machineID: "SYNTHETIC-MID")
    }
    func startProvision(libDir: String, provisioningDir: String, identifier: [UInt8], spim: [UInt8]) async throws -> (cpim: Data, session: UInt32) { throw AnisetteError.invalidArgument }
    func endProvision(libDir: String, provisioningDir: String, identifier: [UInt8], session: UInt32, ptm: [UInt8], tk: [UInt8]) async throws -> Data { throw AnisetteError.invalidArgument }
}

private final class OwnedLookupFixture: URLProtocol, @unchecked Sendable {
    private static let lock = NSLock()
    nonisolated(unsafe) private static var requests = 0
    nonisolated(unsafe) private static var shouldStall = false
    nonisolated(unsafe) private static var started: XCTestExpectation?
    static var requestCount: Int { lock.withLock { requests } }
    static func configure(stall: Bool, started: XCTestExpectation?) {
        lock.withLock { requests = 0; shouldStall = stall; self.started = started }
    }
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        let (stall, expectation) = Self.lock.withLock {
            Self.requests += 1
            return (Self.shouldStall, Self.started)
        }
        expectation?.fulfill()
        if !stall { client?.urlProtocol(self, didFailWithError: URLError(.cannotConnectToHost)) }
    }
    override func stopLoading() { }
}
