import Foundation

/// DER encoding for a self-signed RSA client certificate and parsing PKCS#1 public keys.
enum DER {
    static func value(_ tag: UInt8, _ body: Data) -> Data {
        var length = Data()
        if body.count < 128 { length.append(UInt8(body.count)) }
        else {
            var n = body.count
            var bytes: [UInt8] = []
            while n > 0 { bytes.insert(UInt8(n & 255), at: 0); n >>= 8 }
            length.append(UInt8(128 + bytes.count))
            length.append(contentsOf: bytes)
        }
        return Data([tag]) + length + body
    }
    static func sequence(_ body: Data) -> Data { value(0x30, body) }
    static func integer(_ bytes: Data) -> Data {
        var bytes = bytes
        while bytes.count > 1 && bytes.first == 0 { bytes.removeFirst() }
        if bytes.isEmpty { bytes = Data([0]) }
        if bytes.first! & 128 != 0 { bytes.insert(0, at: 0) }
        return value(2, bytes)
    }
    static let rsa = sequence(Data([6, 9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 1, 5, 0]))
    static let sha256RSA = sequence(Data([6, 9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 11, 5, 0]))
    static func read(_ bytes: [UInt8], _ offset: inout Int, tag: UInt8) throws -> Data {
        guard offset + 2 <= bytes.count, bytes[offset] == tag else { throw WireError.malformed }
        offset += 1
        var length = Int(bytes[offset]); offset += 1
        if length & 128 != 0 {
            let size = length & 127
            guard size > 0, size <= 4, offset + size <= bytes.count else { throw WireError.malformed }
            length = 0
            for _ in 0..<size { length = (length << 8) | Int(bytes[offset]); offset += 1 }
        }
        guard length <= bytes.count - offset else { throw WireError.malformed }
        defer { offset += length }
        return Data(bytes[offset..<offset + length])
    }
    static func rsaComponents(_ pkcs1: Data) throws -> Data {
        var offset = 0
        let sequence = try read(Array(pkcs1), &offset, tag: 0x30)
        offset = 0
        var modulus = try read(Array(sequence), &offset, tag: 2)
        var exponent = try read(Array(sequence), &offset, tag: 2)
        while modulus.count > 1 && modulus.first == 0 { modulus.removeFirst() }
        while exponent.count > 1 && exponent.first == 0 { exponent.removeFirst() }
        return modulus + exponent
    }
}
