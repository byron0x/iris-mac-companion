import Foundation
import CryptoKit
import Darwin

public struct QuarantineReceipt: Codable, Identifiable, Sendable {
    public var id: String
    public var originalPath: String
    public var sha256: String
    public var originalMode: UInt16
    public var date: Date
}
/// Only user-owned regular files in explicitly supported locations are eligible.
/// Parent directories are opened without following symlinks. No root helper or shell is used.
public final class QuarantineStore: @unchecked Sendable {
    public let directory: URL
    private let home: String
    public init(directory: URL, home: String = NSHomeDirectory()) throws {
        self.directory = directory; self.home = home.hasSuffix("/") ? String(home.dropLast()) : home
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let fd = try Self.openDirectory(directory.path); defer { close(fd) }
        var info = stat(); guard fstat(fd, &info) == 0, info.st_uid == getuid() else { throw ScanError.unsafePath }
        guard fchmod(fd, 0o700) == 0 else { throw ScanError.unsafePath }
    }
    public func eligible(_ path: String) -> Bool {
        guard path.hasPrefix("/"), !path.contains("//"), !path.split(separator: "/").contains(where: { $0 == "." || $0 == ".." }), !path.contains("\u{0}"), !path.contains("\n"), !path.contains("\r") else { return false }
        return ["Downloads/", "Desktop/", "Library/LaunchAgents/"].contains { path.hasPrefix(home + "/" + $0) }
            || LocalAssessment.shellFiles.contains(URL(fileURLWithPath: path).lastPathComponent) && URL(fileURLWithPath: path).deletingLastPathComponent().path == home
    }
    static func openDirectory(_ path: String) throws -> Int32 {
        guard path.hasPrefix("/") else { throw ScanError.unsafePath }
        var fd = Darwin.open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard fd >= 0 else { throw ScanError.unsafePath }
        do {
            for part in path.split(separator: "/") {
                guard part != ".", part != ".." else { throw ScanError.unsafePath }
                let next = openat(fd, String(part), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard next >= 0 else { throw ScanError.unsafePath }
                close(fd); fd = next
            }
            return fd
        } catch { close(fd); throw error }
    }
    private func digest(fd: Int32) throws -> String {
        guard lseek(fd, 0, SEEK_SET) >= 0 else { throw ScanError.unsafePath }
        var hash = SHA256(); var buffer = [UInt8](repeating: 0, count: 65536)
        while true { let n = read(fd, &buffer, buffer.count); if n < 0 { throw ScanError.unsafePath }; if n == 0 { break }; hash.update(data: Data(buffer.prefix(n))) }
        return hash.finalize().map { String(format: "%02x", $0) }.joined()
    }
    public func validate(path: String, expectedHash: String) throws {
        guard eligible(path), expectedHash.count == 64 else { throw ScanError.unsafePath }
        let url = URL(fileURLWithPath: path)
        let parent = try Self.openDirectory(url.deletingLastPathComponent().path); defer { close(parent) }
        let fd = openat(parent, url.lastPathComponent, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw ScanError.unsafePath }; defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_uid == getuid(), info.st_nlink == 1 else { throw ScanError.unsafePath }
        guard try digest(fd: fd) == expectedHash else { throw ScanError.changedFile }
    }
    public func quarantine(path: String, expectedHash: String) throws -> QuarantineReceipt {
        guard eligible(path), expectedHash.count == 64 else { throw ScanError.unsafePath }
        let url = URL(fileURLWithPath: path)
        let parent = try Self.openDirectory(url.deletingLastPathComponent().path); defer { close(parent) }
        let fd = openat(parent, url.lastPathComponent, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw ScanError.unsafePath }; defer { close(fd) }
        var before = stat(); guard fstat(fd, &before) == 0, before.st_mode & S_IFMT == S_IFREG, before.st_uid == getuid(), before.st_nlink == 1 else { throw ScanError.unsafePath }
        guard try digest(fd: fd) == expectedHash else { throw ScanError.changedFile }
        let target = try Self.openDirectory(directory.path); defer { close(target) }
        let id = UUID().uuidString.lowercased()
        let receipt = QuarantineReceipt(id: id, originalPath: path, sha256: expectedHash, originalMode: UInt16(before.st_mode & 0o777), date: Date())
        // Save the recovery receipt before moving; failure cannot lose the original location.
        try JSONEncoder().encode(receipt).write(to: directory.appendingPathComponent(id + ".json"), options: .atomic)
        guard renameatx_np(parent, url.lastPathComponent, target, id, UInt32(RENAME_EXCL)) == 0 else { try? FileManager.default.removeItem(at: directory.appendingPathComponent(id + ".json")); throw ScanError.unsafePath }
        var after = stat()
        guard fstatat(target, id, &after, AT_SYMLINK_NOFOLLOW) == 0, after.st_ino == before.st_ino, after.st_dev == before.st_dev, after.st_nlink == 1, try digest(fd: fd) == expectedHash else {
            // Refuse to overwrite a replacement at the original path during rollback.
            _ = renameatx_np(target, id, parent, url.lastPathComponent, UInt32(RENAME_EXCL)); throw ScanError.changedFile
        }
        guard fchmod(fd, 0) == 0 else { _ = renameatx_np(target, id, parent, url.lastPathComponent, UInt32(RENAME_EXCL)); throw ScanError.unsafePath }
        return receipt
    }
    public func receipts() -> [QuarantineReceipt] {
        ((try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)) ?? []).filter { $0.pathExtension == "json" }.compactMap { url in
            guard let data = try? Data(contentsOf: url), let receipt = try? JSONDecoder().decode(QuarantineReceipt.self, from: data), UUID(uuidString: receipt.id) != nil, eligible(receipt.originalPath), receipt.id + ".json" == url.lastPathComponent, FileManager.default.fileExists(atPath: directory.appendingPathComponent(receipt.id).path) else { return nil }
            return receipt
        }.sorted { $0.date > $1.date }
    }
    public func restore(_ receipt: QuarantineReceipt) throws {
        guard UUID(uuidString: receipt.id) != nil, eligible(receipt.originalPath), receipts().contains(where: { $0.id == receipt.id && $0.originalPath == receipt.originalPath && $0.sha256 == receipt.sha256 }) else { throw ScanError.unsafePath }
        let target = try Self.openDirectory(directory.path); defer { close(target) }
        let original = URL(fileURLWithPath: receipt.originalPath)
        let parent = try Self.openDirectory(original.deletingLastPathComponent().path); defer { close(parent) }
        // Temporarily grant owner read permission while the file remains inside the private quarantine.
        var before = stat()
        guard fstatat(target, receipt.id, &before, AT_SYMLINK_NOFOLLOW) == 0, before.st_mode & S_IFMT == S_IFREG, before.st_uid == getuid(), before.st_nlink == 1 else { throw ScanError.unsafePath }
        guard fchmodat(target, receipt.id, 0o400, AT_SYMLINK_NOFOLLOW) == 0 else { throw ScanError.unsafePath }
        let fd = openat(target, receipt.id, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw ScanError.unsafePath }; defer { close(fd) }
        var info = stat(); guard fstat(fd, &info) == 0, info.st_ino == before.st_ino, info.st_dev == before.st_dev, info.st_mode & S_IFMT == S_IFREG, info.st_nlink == 1, info.st_uid == getuid(), try digest(fd: fd) == receipt.sha256 else { _ = fchmod(fd, 0); throw ScanError.changedFile }
        guard renameatx_np(target, receipt.id, parent, original.lastPathComponent, UInt32(RENAME_EXCL)) == 0 else { _ = fchmod(fd, 0); throw ScanError.commandFailed("A file already exists at the original location. IRIS has kept the quarantined copy.") }
        var restored = stat()
        guard fstatat(parent, original.lastPathComponent, &restored, AT_SYMLINK_NOFOLLOW) == 0, restored.st_ino == info.st_ino, restored.st_dev == info.st_dev, restored.st_nlink == 1, try digest(fd: fd) == receipt.sha256 else {
            _ = renameatx_np(parent, original.lastPathComponent, target, receipt.id, UInt32(RENAME_EXCL)); _ = fchmod(fd, 0); throw ScanError.changedFile
        }
        guard fchmod(fd, mode_t(receipt.originalMode & 0o700)) == 0 else { throw ScanError.commandFailed("The file was restored, but macOS could not restore its permissions. Review it in Finder.") }
        try? FileManager.default.removeItem(at: directory.appendingPathComponent(receipt.id + ".json"))
    }
    /// Explicit permanent removal of a verified quarantined regular file only.
    public func remove(_ receipt: QuarantineReceipt) throws {
        guard UUID(uuidString: receipt.id) != nil, receipts().contains(where: { $0.id == receipt.id && $0.originalPath == receipt.originalPath && $0.sha256 == receipt.sha256 }) else { throw ScanError.unsafePath }
        let target = try Self.openDirectory(directory.path); defer { close(target) }
        var before = stat()
        guard fstatat(target, receipt.id, &before, AT_SYMLINK_NOFOLLOW) == 0, before.st_mode & S_IFMT == S_IFREG, before.st_uid == getuid(), before.st_nlink == 1 else { throw ScanError.unsafePath }
        guard fchmodat(target, receipt.id, 0o400, AT_SYMLINK_NOFOLLOW) == 0 else { throw ScanError.unsafePath }
        let fd = openat(target, receipt.id, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw ScanError.unsafePath }; defer { _ = fchmod(fd, 0); close(fd) }
        var info = stat(), current = stat()
        guard fstat(fd, &info) == 0, info.st_ino == before.st_ino, info.st_dev == before.st_dev, info.st_mode & S_IFMT == S_IFREG, info.st_uid == getuid(), info.st_nlink == 1,
              try digest(fd: fd) == receipt.sha256,
              fstatat(target, receipt.id, &current, AT_SYMLINK_NOFOLLOW) == 0, current.st_ino == info.st_ino, current.st_dev == info.st_dev else { throw ScanError.changedFile }
        guard unlinkat(target, receipt.id, 0) == 0 else { throw ScanError.unsafePath }
        _ = unlinkat(target, receipt.id + ".json", 0)
    }
}
