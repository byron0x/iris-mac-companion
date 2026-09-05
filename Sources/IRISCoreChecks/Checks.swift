import Foundation
import CryptoKit
import IRISCore

final class CoreChecks {
    var cleanups: [() -> Void] = []
    func addTeardownBlock(_ work: @escaping () -> Void) { cleanups.append(work) }
    deinit { cleanups.forEach { $0() } }
    func testEncryptedMessagesRejectTamperingWrongDirectionAndExpiry() throws {
        let key = SymmetricKey(data: Data(repeating: 7, count: 32))
        let now = Date(timeIntervalSince1970: 1_800_000_000)

        // Independent Node.js AES-GCM vector, matching the browser wire format.
        let vector = #"{"version":1,"id":"11111111-2222-4333-8444-555555555555","direction":"command","createdAt":1800000000000,"box":"CQkJCQkJCQkJCQkJXKfl98qZrg-CWOlLhYvN_anEGiguYskcfMl-f4HMrC-U"}"#
        let interoperable = try JSONDecoder().decode(Envelope.self, from: Data(vector.utf8))
        try checkEqual(try RelayCrypto.open(interoperable, as: DeviceCommand.self, key: key, direction: "command", maximumAge: 120, now: now).action, "scan")
        let box = try RelayCrypto.seal(DeviceCommand(action: "scan"), key: key, direction: "command", now: now)
        try checkEqual(try RelayCrypto.open(box, as: DeviceCommand.self, key: key, direction: "command", maximumAge: 120, now: now).action, "scan")
        try checkThrows(try RelayCrypto.open(box, as: DeviceCommand.self, key: key, direction: "report", maximumAge: 120, now: now))
        try checkThrows(try RelayCrypto.open(box, as: DeviceCommand.self, key: key, direction: "command", maximumAge: 120, now: now.addingTimeInterval(121)))
        try checkThrows(try RelayCrypto.open(box, as: DeviceCommand.self, key: SymmetricKey(size: .bits256), direction: "command", maximumAge: 120, now: now))
        var json = try JSONSerialization.jsonObject(with: JSONEncoder().encode(box)) as! [String: Any]
        json["createdAt"] = box.createdAt + 1
        let changed = try JSONDecoder().decode(Envelope.self, from: JSONSerialization.data(withJSONObject: json))
        try checkThrows(try RelayCrypto.open(changed, as: DeviceCommand.self, key: key, direction: "command", maximumAge: 120, now: now))
        try checkThrows(try RelayCrypto.decodeKey("short"))
    }
    func testInventoryPreservesBinaryAndStartupPathsWithoutCallingUnsignedMalware() throws {
        let json = #"{"Launch Items":[{"name":"Example","path":"/Users/fixture/Applications/Example.app/Contents/MacOS/Example","plist":"/Users/fixture/Library/LaunchAgents/io.example.plist","signature(s)":{"signatureStatus":0,"signatureAuthorities":["Developer ID Application: Example"]}},{"name":"Unknown","path":"/Users/fixture/Downloads/unknown","signature(s)":{"signatureStatus":-67062}},{"name":"Command only","command":"example --start"}]}"#
        let result = try InventoryParser.parse(Data(json.utf8), home: "/Users/fixture")
        try checkEqual(result.findings.count, 2)
        try checkEqual(result.skippedItems, 1)
        try checkFalse(result.findings.contains { $0.level == .threat })
        let startup = try unwrap(result.findings.first { $0.title == "Example" })
        try checkEqual(startup.action, .disableStartup)
        try checkEqual(startup.level, .information)
        try checkEqual(result.paths[startup.id], "/Users/fixture/Library/LaunchAgents/io.example.plist")
        try checkTrue(result.scanPaths.contains("/Users/fixture/Applications/Example.app/Contents/MacOS/Example"))
        try checkTrue(startup.location.hasPrefix("~/"))
        try checkThrows(try InventoryParser.parse(Data("{\"bad\":1}".utf8)))
    }
    func fixture() throws -> (URL, QuarantineStore) {
        let base = URL(fileURLWithPath: "/private/tmp").appendingPathComponent("iris-test-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: base.appendingPathComponent("Downloads"), withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: base) }
        return (base, try QuarantineStore(directory: base.appendingPathComponent("Quarantine"), home: base.path))
    }
    func testQuarantineAndRestoreNeverOverwriteReplacement() throws {
        let (base, store) = try fixture(); let file = base.appendingPathComponent("Downloads/example.txt")
        let original = Data("harmless fixture".utf8); try original.write(to: file)
        let receipt = try store.quarantine(path: file.path, expectedHash: fileSHA256(file))
        try checkFalse(FileManager.default.fileExists(atPath: file.path))
        try checkEqual(store.receipts().count, 1)
        let attributes = try FileManager.default.attributesOfItem(atPath: store.directory.appendingPathComponent(receipt.id).path)
        try checkEqual((attributes[.posixPermissions] as! NSNumber).intValue, 0)
        try Data("replacement".utf8).write(to: file)
        try checkThrows(try store.restore(receipt))
        try checkEqual(try String(contentsOf: file), "replacement")
        try FileManager.default.removeItem(at: file)
        try store.restore(receipt)
        try checkEqual(try Data(contentsOf: file), original)
        try checkTrue(store.receipts().isEmpty)
    }
    func testCleanupRejectsChangedFilesSymlinksAndHardlinks() throws {
        let (base, store) = try fixture(); let file = base.appendingPathComponent("Downloads/example.txt")
        try Data("before".utf8).write(to: file); let hash = try fileSHA256(file)
        try Data("after".utf8).write(to: file)
        try checkThrows(try store.quarantine(path: file.path, expectedHash: hash))
        let link = base.appendingPathComponent("Downloads/symlink")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: file)
        try checkThrows(try store.quarantine(path: link.path, expectedHash: fileSHA256(file)))
        let hardlink = base.appendingPathComponent("Downloads/hardlink")
        try FileManager.default.linkItem(at: file, to: hardlink)
        try checkThrows(try store.quarantine(path: hardlink.path, expectedHash: fileSHA256(file)))
        try checkTrue(FileManager.default.fileExists(atPath: file.path))
        try checkFalse(store.eligible("/System/Library/example"))
        try checkFalse(store.eligible(base.path + "/Downloads/../elsewhere"))
        let outside = base.appendingPathComponent("Outside")
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
        let redirected = base.appendingPathComponent("Downloads/redirected")
        try FileManager.default.createSymbolicLink(at: redirected, withDestinationURL: outside)
        let target = outside.appendingPathComponent("file"); try Data("safe".utf8).write(to: target)
        try checkThrows(try store.quarantine(path: redirected.appendingPathComponent("file").path, expectedHash: fileSHA256(target)))
    }
    func testCancelledRunnerCannotStartAnotherProcessUntilExplicitReset() throws {
        let runner = ProcessRunner(); runner.cancel()
        try checkThrows(try runner.run(URL(fileURLWithPath: "/usr/bin/true"), []))
        runner.resetCancellation()
        try checkEqual(try runner.run(URL(fileURLWithPath: "/usr/bin/true"), []).status, 0)
    }
}

struct CheckFailure: Error, CustomStringConvertible { let description: String }
func checkEqual<T: Equatable>(_ a: @autoclosure () throws -> T, _ b: @autoclosure () throws -> T, file: String = #fileID, line: Int = #line) throws { if try a() != b() { throw CheckFailure(description: "Equality check failed at \(file):\(line)") } }
func checkTrue(_ value: @autoclosure () throws -> Bool, file: String = #fileID, line: Int = #line) throws { if try !value() { throw CheckFailure(description: "Expected true at \(file):\(line)") } }
func checkFalse(_ value: @autoclosure () throws -> Bool, file: String = #fileID, line: Int = #line) throws { try checkTrue(!value(), file: file, line: line) }
func checkThrows<T>(_ value: @autoclosure () throws -> T, file: String = #fileID, line: Int = #line) throws { do { _ = try value() } catch { return }; throw CheckFailure(description: "Expected rejection at \(file):\(line)") }
func unwrap<T>(_ value: T?) throws -> T { guard let value else { throw CheckFailure(description: "Expected a value") }; return value }
@main struct VerifyCore {
    static func main() throws {
        let checks = CoreChecks()
        let cases: [(String, () throws -> Void)] = [
            ("Authenticated encryption, tampering and expiry", checks.testEncryptedMessagesRejectTamperingWrongDirectionAndExpiry),
            ("Startup inventory paths and conservative classification", checks.testInventoryPreservesBinaryAndStartupPathsWithoutCallingUnsignedMalware),
            ("Quarantine, restore and replacement protection", checks.testQuarantineAndRestoreNeverOverwriteReplacement),
            ("Changed file, symlink and hardlink rejection", checks.testCleanupRejectsChangedFilesSymlinksAndHardlinks),
            ("Cancellation prevents subsequent process execution", checks.testCancelledRunnerCannotStartAnotherProcessUntilExplicitReset)
        ]
        for (name, run) in cases { print("CHECK: " + name); fflush(stdout); try run(); print("PASS: " + name); fflush(stdout) }
        print("All \(cases.count) native core checks passed using temporary fixtures.")
    }
}
