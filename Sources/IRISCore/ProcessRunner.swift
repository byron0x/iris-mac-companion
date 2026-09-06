import Foundation
import CryptoKit
import Darwin
public struct ProcessOutput: Sendable { public let status: Int32; public let data: Data; public let errors: Data }
public final class ProcessRunner: @unchecked Sendable {
    private let lock = NSLock()
    private var running: Process?
    private var cancelled = false
    public func resetCancellation() { lock.lock(); cancelled = false; lock.unlock() }
    public func checkCancellation() throws { lock.lock(); let stopped = cancelled; lock.unlock(); if stopped { throw CancellationError() } }
    public init() {}
    public func cancel() { lock.lock(); cancelled = true; let p = running; lock.unlock(); if let p, p.isRunning { p.terminate(); DispatchQueue.global().asyncAfter(deadline: .now() + 3) { if p.isRunning { kill(p.processIdentifier, SIGKILL) } } } }
    public func run(_ executable: URL, _ arguments: [String], timeout: TimeInterval = 120, environment: [String: String] = [:], onOutput: (@Sendable (Data) -> Void)? = nil) throws -> ProcessOutput {
        let p = Process(); p.executableURL = executable; p.arguments = arguments
        let out = Pipe(); let err = Pipe(); p.standardOutput = out; p.standardError = err; p.standardInput = FileHandle.nullDevice
        p.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": NSHomeDirectory(), "LANG": "en_US.UTF-8"].merging(environment) { _, value in value }
        lock.lock(); if cancelled { lock.unlock(); throw CancellationError() }; running = p
        do { try p.run(); lock.unlock() } catch { running = nil; lock.unlock(); throw error }
        defer { lock.lock(); running = nil; lock.unlock() }
        let limit = 24_000_000
        let output = Buffer(); let errors = Buffer(); let group = DispatchGroup()
        for (pipe, buffer) in [(out, output), (err, errors)] {
            group.enter(); DispatchQueue.global().async {
                defer { group.leave() }
                while true {
                    let chunk = pipe.fileHandleForReading.availableData
                    if chunk.isEmpty { break }
                    if buffer.data.count + chunk.count > limit { buffer.overflow = true; if p.isRunning { p.terminate() }; continue }
                    buffer.data.append(chunk)
                    if pipe === out { onOutput?(chunk) }
                }
            }
        }
        let stop = DispatchWorkItem { if p.isRunning { p.terminate(); DispatchQueue.global().asyncAfter(deadline: .now() + 3) { if p.isRunning { kill(p.processIdentifier, SIGKILL) } } } }
        DispatchQueue.global().asyncAfter(deadline: .now() + timeout, execute: stop)
        p.waitUntilExit(); stop.cancel(); group.wait()
        try checkCancellation()
        if output.overflow || errors.overflow { throw ScanError.commandFailed("The scanner produced too much output. Its review is incomplete.") }
        return ProcessOutput(status: p.terminationStatus, data: output.data, errors: errors.data)
    }
    private final class Buffer: @unchecked Sendable { var data = Data(); var overflow = false }
}
public func fileSHA256(_ url: URL) throws -> String {
    let handle = try FileHandle(forReadingFrom: url); defer { try? handle.close() }
    var hasher = SHA256()
    while let data = try handle.read(upToCount: 1024 * 1024), !data.isEmpty { hasher.update(data: data) }
    return hasher.finalize().map { String(format: "%02x", $0) }.joined()
}
