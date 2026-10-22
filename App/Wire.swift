import Foundation

enum WireError: Error { case malformed, oversized }

/// The small subset of protobuf wire types used by Android TV Remote v2.
enum PB {
    struct Field {
        let number: Int
        let integer: UInt64?
        let bytes: Data?
    }
    static func varint(_ value: UInt64) -> Data {
        var value = value
        var out = Data()
        repeat {
            let byte = UInt8(value & 127)
            value >>= 7
            out.append(byte | (value > 0 ? 128 : 0))
        } while value > 0
        return out
    }
    static func int(_ field: Int, _ value: UInt64) -> Data {
        varint(UInt64(field << 3)) + varint(value)
    }
    static func blob(_ field: Int, _ value: Data) -> Data {
        varint(UInt64((field << 3) | 2)) + varint(UInt64(value.count)) + value
    }
    static func string(_ field: Int, _ value: String) -> Data {
        blob(field, Data(value.utf8))
    }
    static func readVarint(_ data: [UInt8], _ offset: inout Int) throws -> UInt64 {
        var value: UInt64 = 0
        for i in 0..<10 {
            guard offset < data.count else { throw WireError.malformed }
            let byte = data[offset]
            offset += 1
            if i == 9 && byte > 1 { throw WireError.malformed }
            value |= UInt64(byte & 127) << (i * 7)
            if byte & 128 == 0 { return value }
        }
        throw WireError.malformed
    }
    static func fields(_ payload: Data) throws -> [Field] {
        let data = Array(payload)
        var offset = 0
        var fields: [Field] = []
        while offset < data.count {
            let tag = try readVarint(data, &offset)
            guard tag >> 3 > 0, tag >> 3 <= 0x1fffffff else { throw WireError.malformed }
            let number = Int(tag >> 3)
            switch tag & 7 {
            case 0:
                fields.append(Field(number: number, integer: try readVarint(data, &offset), bytes: nil))
            case 2:
                let count = try readVarint(data, &offset)
                guard count <= UInt64(data.count - offset) else { throw WireError.malformed }
                fields.append(Field(number: number, integer: nil, bytes: Data(data[offset..<offset + Int(count)])))
                offset += Int(count)
            case 1, 5:
                let count = tag & 7 == 1 ? 8 : 4
                guard data.count - offset >= count else { throw WireError.malformed }
                offset += count
            default: throw WireError.malformed
            }
        }
        return fields
    }
}

extension Array where Element == PB.Field {
    func integer(_ n: Int) -> UInt64 { first { $0.number == n }?.integer ?? 0 }
    func blob(_ n: Int) -> Data? { first { $0.number == n }?.bytes }
}

/// TCP may split or combine messages at any byte, including inside the length prefix.
struct FrameBuffer {
    private var buffer = Data()
    mutating func append(_ chunk: Data) throws -> [Data] {
        buffer.append(chunk)
        var frames: [Data] = []
        while !buffer.isEmpty {
            let bytes = Array(buffer.prefix(5))
            guard let end = bytes.firstIndex(where: { $0 & 128 == 0 }) else {
                if bytes.count == 5 { throw WireError.oversized }
                break
            }
            var offset = 0
            let length = try PB.readVarint(bytes, &offset)
            guard length > 0, length <= 1_048_576 else { throw WireError.oversized }
            guard buffer.count >= end + 1 + Int(length) else { break }
            frames.append(Data(buffer.dropFirst(end + 1).prefix(Int(length))))
            buffer = Data(buffer.dropFirst(end + 1 + Int(length)))
        }
        return frames
    }
}

enum TVMessage {
    static let encoding = PB.int(1, 3) + PB.int(2, 6)
    static func pairing(_ field: Int, _ body: Data) -> Data {
        PB.int(1, 2) + PB.int(2, 200) + PB.blob(field, body)
    }
    static func key(_ code: UInt64) -> Data {
        PB.blob(10, PB.int(1, code) + PB.int(2, 3))
    }
}
