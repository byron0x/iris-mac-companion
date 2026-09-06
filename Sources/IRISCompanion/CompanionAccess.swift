import Foundation

struct CompanionAccess: Codable {
    var version: Int
    var plan: String
    var unlimited: Bool
    var monitoring: Bool
    var remaining: Int?
    var resetsAt: Double
    var checkedAt: Double
    var validUntil: Double
    var current: Bool { version == 1 && ["free", "pro", "god_mode"].contains(plan) && validUntil > Date().timeIntervalSince1970 * 1000 && validUntil <= Date().timeIntervalSince1970 * 1000 + 330000 }
}
struct WatchState: Codable {
    var enabled = false
    var status = "off"
    var message = "Enable Pro monitoring to check changes in Downloads, Desktop and your user LaunchAgents folder while IRIS is running."
    var checkedAt: Double?
    var filesChecked = 0
    var matches = 0
}
