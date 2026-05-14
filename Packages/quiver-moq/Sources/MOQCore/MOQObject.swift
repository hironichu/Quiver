/// MOQ Object Model
///
/// Defines the core data structures for Media Over QUIC (MOQ).
/// Based on draft-ietf-moq-transport.

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import QUICCore

/// Header for a MOQ Object.
///
/// Uniquely identifies an object within a track and provides
/// scheduling metadata (priority).
public struct MOQObjectHeader: Sendable, Hashable, CustomStringConvertible {
    /// The Track Identifier.
    /// In a full implementation, this might be a Subscribe ID or Track Alias.
    public let trackID: UInt64

    /// The Group Identifier.
    /// Objects are grouped into "groups" (e.g. GOPs in video).
    /// Groups are valid units for seeking and dropping.
    public let groupID: UInt64

    /// The Object Identifier (within the group).
    /// Monotonically increasing within a group.
    public let objectID: UInt64

    /// The transmission priority.
    /// Lower priority objects main be dropped during congestion.
    /// Range: 0 (Low) to 255 (High).
    /// *Note*: This maps to `DatagramSendingStrategy.priority`.
    public let priority: UInt8

    /// The object status (e.g., Normal, EndOfGroup, EndOfTrack).
    public let status: MOQObjectStatus

    public init(
        trackID: UInt64,
        groupID: UInt64,
        objectID: UInt64,
        priority: UInt8,
        status: MOQObjectStatus = .normal
    ) {
        self.trackID = trackID
        self.groupID = groupID
        self.objectID = objectID
        self.priority = priority
        self.status = status
    }

    public var description: String {
        "MOQObject(T:\(trackID) G:\(groupID) O:\(objectID) P:\(priority) S:\(status))"
    }
}

/// Status of the object.
public enum MOQObjectStatus: UInt8, Sendable, Hashable, CustomStringConvertible {
    /// Normal object payload.
    case normal = 0x00

    /// Object does not exist (gap).
    case doesNotExist = 0x01

    /// End of Group marker.
    case endOfGroup = 0x02

    /// End of Track marker.
    case endOfTrack = 0x03

    /// End of Datagram (implicit, for stream mapping).
    case endOfDatagram = 0x04

    public var description: String {
        switch self {
        case .normal: return "Normal"
        case .doesNotExist: return "DoesNotExist"
        case .endOfGroup: return "EndOfGroup"
        case .endOfTrack: return "EndOfTrack"
        case .endOfDatagram: return "EndOfDatagram"
        }
    }
}

/// A complete MOQ Object.
///
/// Represents an atomic unit of media data (e.g. a video frame or audio packet).
public struct MOQObject: Sendable {
    /// The object header.
    public let header: MOQObjectHeader

    /// The object payload data.
    public let payload: Data

    public init(header: MOQObjectHeader, payload: Data) {
        self.header = header
        self.payload = payload
    }

    /// Encodes the object into the MOQ wire format.
    public func encode() -> Data {
        var data = Data()
        Varint(header.trackID).encode(to: &data)
        Varint(header.groupID).encode(to: &data)
        Varint(header.objectID).encode(to: &data)
        data.append(header.priority)
        data.append(header.status.rawValue)
        data.append(payload)
        return data
    }
}

extension MOQObject {
    /// Decodes an object from the MOQ wire format.
    public static func decode(from data: Data) throws -> MOQObject {
        guard !data.isEmpty else { throw MOQError.invalidObject("Empty data") }
        var offset = 0

        let (trackAlias, tLen) = try Varint.decode(from: data.dropFirst(offset))
        offset += tLen

        let (groupID, gLen) = try Varint.decode(from: data.dropFirst(offset))
        offset += gLen

        let (objectID, oLen) = try Varint.decode(from: data.dropFirst(offset))
        offset += oLen

        guard offset + 2 <= data.count else { throw MOQError.invalidObject("Truncated header") }
        let priority = data[offset]
        offset += 1
        guard let status = MOQObjectStatus(rawValue: data[offset]) else {
            throw MOQError.invalidObject("Invalid status")
        }
        offset += 1

        return MOQObject(
            header: MOQObjectHeader(
                trackID: trackAlias.value,
                groupID: groupID.value,
                objectID: objectID.value,
                priority: priority,
                status: status
            ),
            payload: data.dropFirst(offset)
        )
    }
}

public enum MOQError: Error {
    case invalidObject(String)
    case unknownTrack(UInt64)
}
