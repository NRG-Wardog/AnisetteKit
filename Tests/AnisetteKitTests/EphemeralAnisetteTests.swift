// No native provider or network calls. All blobs/headers are synthetic fixtures.
import Foundation
import Testing
@testable import AnisetteKit

private final class EphemeralFakeProvider: AnisetteDataProvider, @unchecked Sendable {
    let requiresLocalLibraries: Bool
    private let lock = NSLock()
    private var calls = 0
    var callCount: Int { lock.withLock { calls } }
    init(requiresLocalLibraries: Bool = false) { self.requiresLocalLibraries = requiresLocalLibraries }
    func getAnisetteHeaders(libDir: String, provisioningDir: String, identifier: [UInt8], adiPb: [UInt8]) async throws -> AnisetteDataResponse {
        lock.withLock { calls += 1 }
        #expect(libDir.isEmpty)
        #expect(adiPb == [1, 2, 3])
        return AnisetteDataResponse(oneTimePassword: "SYNTHETIC-OTP", machineID: "SYNTHETIC-MID", routingInfo: "42")
    }
    func startProvision(libDir: String, provisioningDir: String, identifier: [UInt8], spim: [UInt8]) async throws -> (cpim: Data, session: UInt32) {
        Issue.record("Unexpected provisioning")
        throw AnisetteError.invalidArgument
    }
    func endProvision(libDir: String, provisioningDir: String, identifier: [UInt8], session: UInt32, ptm: [UInt8], tk: [UInt8]) async throws -> Data {
        Issue.record("Unexpected provisioning")
        throw AnisetteError.invalidArgument
    }
}

@Suite("EphemeralAnisetteTests: synthetic remote-only storage")
struct EphemeralAnisetteTests {
    @Test func existingBlobLeavesSentinelFilesUnchangedAndIgnoresDiskRouting() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let id = UUID()
        let directory = root.appendingPathComponent(id.uuidString.lowercased())
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let blob = directory.appendingPathComponent("adi.pb")
        let routing = directory.appendingPathComponent("rinfo")
        try Data([9, 9, 9]).write(to: blob)
        try Data("unrelated-local-routing".utf8).write(to: routing)
        let provider = EphemeralFakeProvider()
        let client = try AnisetteClient(provisioningDir: root, provider: provider,
            requestTransport: { _ in Issue.record("Unexpected network"); throw AnisetteError.invalidArgument })
        let result = try await client.getAnisetteData(identifier: id, storage: .ephemeral(existingBlob: Data([1, 2, 3])))
        #expect(result.newBlob == nil)
        #expect(result.headers[AnisetteConstants.Headers.routingInfo] == "42")
        #expect(try Data(contentsOf: blob) == Data([9, 9, 9]))
        #expect(try Data(contentsOf: routing) == Data("unrelated-local-routing".utf8))
        #expect(provider.callCount == 1)
    }
    @Test func rejectsNativeProviderBeforeAnyProviderCalls() async throws {
        let root = FileManager.default.temporaryDirectory
        let provider = EphemeralFakeProvider(requiresLocalLibraries: true)
        let client = try AnisetteClient(provisioningDir: root, requiredLibraries: [], provider: provider,
            libraryDirectoryResolver: { root })
        do {
            _ = try await client.getAnisetteData(identifier: UUID(), storage: .ephemeral(existingBlob: Data([1, 2, 3])))
            Issue.record("Native provider must be rejected")
        } catch { #expect((error as? AnisetteError) == .invalidArgument) }
        #expect(provider.callCount == 0)
    }
    @Test func cancelledTaskDoesNotReachProvider() async throws {
        let provider = EphemeralFakeProvider()
        let client = try AnisetteClient(provisioningDir: URL(fileURLWithPath: "/unused"), provider: provider)
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await client.getAnisetteData(identifier: UUID(), storage: .ephemeral(existingBlob: Data([1, 2, 3])))
        }
        do { _ = try await task.value; Issue.record("Expected cancellation") }
        catch { #expect(error is CancellationError) }
        #expect(provider.callCount == 0)
    }
}
