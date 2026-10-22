import XCTest
import Security
@testable import MiBoxRemote

final class ProtocolTests: XCTestCase {
    func testEveryTCPBoundaryAndCombinedFrames() throws {
        let first = PB.blob(90, PB.string(1, String(repeating: "أ", count: 140)))
        let second = TVMessage.key(23)
        let stream = PB.varint(UInt64(first.count)) + first + PB.varint(UInt64(second.count)) + second
        for boundary in 0...stream.count {
            var decoder = FrameBuffer()
            let a = try decoder.append(Data(stream.prefix(boundary)))
            let b = try decoder.append(Data(stream.dropFirst(boundary)))
            XCTAssertEqual(a + b, [first, second], "split at \(boundary)")
        }
        var decoder = FrameBuffer()
        var decoded: [Data] = []
        for byte in stream { decoded += try decoder.append(Data([byte])) }
        XCTAssertEqual(decoded, [first, second])
    }
    func testRejectsInvalidFramesAndFields() throws {
        var decoder = FrameBuffer()
        XCTAssertThrowsError(try decoder.append(Data([0x80, 0x80, 0x80, 0x80, 0x80])))
        var oversized = FrameBuffer()
        XCTAssertThrowsError(try oversized.append(PB.varint(1_048_577)))
        XCTAssertThrowsError(try PB.fields(Data([0x0a, 5, 1])))
        XCTAssertThrowsError(try PB.fields(Data([0])))
        XCTAssertThrowsError(try PB.fields(Data([8] + Array(repeating: UInt8(255), count: 10))))
    }
    func testProtocolFixtures() throws {
        XCTAssertEqual(TVMessage.key(23), Data([0x52, 4, 8, 23, 16, 3]))
        XCTAssertEqual(TVMessage.key(164), Data([0x52, 5, 8, 0xa4, 1, 16, 3]))
        let fields = try PB.fields(TVMessage.pairing(30, PB.blob(1, TVMessage.encoding) + PB.int(2, 1)))
        XCTAssertEqual(fields.integer(1), 2)
        XCTAssertEqual(fields.integer(2), 200)
        let configuration = try PB.fields(XCTUnwrap(fields.blob(30)))
        XCTAssertEqual(configuration.integer(2), 1)
        let encoding = try PB.fields(XCTUnwrap(configuration.blob(1)))
        XCTAssertEqual(encoding.integer(1), 3)
        XCTAssertEqual(encoding.integer(2), 6)
        let unicode = "جهاز شاومي 📺"
        XCTAssertEqual(try PB.fields(PB.string(1, unicode)).blob(1), Data(unicode.utf8))
    }
    func testDERLengthsAndUnsignedRSAComponents() throws {
        for count in [0, 1, 127, 128, 255, 256, 2048] {
            let body = Data(repeating: 42, count: count)
            var offset = 0
            XCTAssertEqual(try DER.read(Array(DER.sequence(body)), &offset, tag: 0x30), body)
        }
        let key = DER.sequence(DER.integer(Data([0x80, 1])) + DER.integer(Data([1, 0, 1])))
        XCTAssertEqual(try DER.rsaComponents(key), Data([0x80, 1, 1, 0, 1]))
        var offset = 0
        XCTAssertThrowsError(try DER.read([0x30, 0x82, 0xff], &offset, tag: 0x30))
    }
    func testIdentityPersistsAndCertificateValidates() throws {
        let first = try ClientIdentity()
        let second = try ClientIdentity()
        var a: SecCertificate?
        var b: SecCertificate?
        XCTAssertEqual(SecIdentityCopyCertificate(first.identity, &a), errSecSuccess)
        XCTAssertEqual(SecIdentityCopyCertificate(second.identity, &b), errSecSuccess)
        let cert = try XCTUnwrap(a)
        XCTAssertEqual(SecCertificateCopyData(cert) as Data, SecCertificateCopyData(try XCTUnwrap(b)) as Data)
        var trust: SecTrust?
        XCTAssertEqual(SecTrustCreateWithCertificates(cert, SecPolicyCreateBasicX509(), &trust), errSecSuccess)
        let validTrust = try XCTUnwrap(trust)
        XCTAssertEqual(SecTrustSetAnchorCertificates(validTrust, [cert] as CFArray), errSecSuccess)
        XCTAssertEqual(SecTrustSetAnchorCertificatesOnly(validTrust, true), errSecSuccess)
        var error: CFError?
        XCTAssertTrue(SecTrustEvaluateWithError(validTrust, &error), String(describing: error))
        var signingError: Unmanaged<CFError>?
        let bytes = try XCTUnwrap(SecKeyCopyExternalRepresentation(first.publicKey, &signingError) as Data?)
        XCTAssertEqual(try DER.rsaComponents(bytes).count, 259)
    }
}
