/// Role a device plays for one authenticated connection. A single install can
/// initiate one connection and respond on another; the role is not global.
public enum DeviceRole: UInt8, Sendable, Equatable, CaseIterable {
    case host = 1
    case client = 2
}
