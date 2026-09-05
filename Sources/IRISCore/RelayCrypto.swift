import Foundation
import CryptoKit

public struct Envelope: Codable, Sendable {
    public var version = 1
    public let id: String
    public let direction: String
    public let createdAt: Double
    public let box: String
}
public struct DeviceCommand: Codable, Sendable {
    public let action: String
    public let findingId: String?
    public let reportId: String?
    public init(action: String, findingId: String? = nil, reportId: String? = nil) { self.action = action; self.findingId = findingId; self.reportId = reportId }
}
public enum RelayCrypto {
    public static func decodeKey(_ text: String) throws -> SymmetricKey {
        guard let bytes = Data(base64URL: text), bytes.count == 32 else { throw ScanError.invalidPairing }
        return SymmetricKey(data: bytes)
    }
    public static func seal<T: Encodable>(_ value: T, key: SymmetricKey, direction: String, now: Date = Date()) throws -> Envelope {
        let id = UUID().uuidString.lowercased(); let created = floor(now.timeIntervalSince1970 * 1000)
        let aad = Data("iris-device-v1:\(direction):\(id):\(Int64(created))".utf8)
        let box = try AES.GCM.seal(JSONEncoder().encode(value), using: key, authenticating: aad)
        guard let combined = box.combined else { throw ScanError.invalidEnvelope }
        return Envelope(id: id, direction: direction, createdAt: created, box: combined.base64URLEncodedString())
    }
    public static func open<T: Decodable>(_ value: Envelope, as type: T.Type, key: SymmetricKey, direction: String, maximumAge: TimeInterval, now: Date = Date()) throws -> T {
        guard value.version == 1, value.direction == direction, UUID(uuidString: value.id) != nil, value.createdAt.isFinite,
              value.createdAt.rounded(.down) == value.createdAt,
              value.createdAt <= now.timeIntervalSince1970 * 1000 + 30_000,
              value.createdAt >= (now.timeIntervalSince1970 - maximumAge) * 1000,
              let combined = Data(base64URL: value.box), combined.count <= 1_000_000 else { throw ScanError.invalidEnvelope }
        let aad = Data("iris-device-v1:\(direction):\(value.id):\(Int64(value.createdAt))".utf8)
        do { return try JSONDecoder().decode(type, from: AES.GCM.open(AES.GCM.SealedBox(combined: combined), using: key, authenticating: aad)) }
        catch { throw ScanError.invalidEnvelope }
    }
}
public extension Data {
    init?(base64URL: String) {
        guard base64URL.range(of: "^[A-Za-z0-9_-]+$", options: .regularExpression) != nil else { return nil }
        var text = base64URL.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        text += String(repeating: "=", count: (4 - text.count % 4) % 4)
        self.init(base64Encoded: text)
    }
    func base64URLEncodedString() -> String { base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "") }
}
