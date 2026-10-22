import Foundation
import Security

enum RemoteError: LocalizedError {
    case message(String)
    var errorDescription: String? {
        if case .message(let text) = self { return text }
        return nil
    }
}

final class ClientIdentity {
    let identity: SecIdentity
    let publicKey: SecKey
    private static let tag = Data("app.miboxremote.rsa.v1".utf8)
    private static let certificateLabel = "MiBox Remote Client v1"

    init() throws {
        let keyQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Self.tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecReturnRef as String: true
        ]
        var keyItem: CFTypeRef?
        let status = SecItemCopyMatching(keyQuery as CFDictionary, &keyItem)
        let key: SecKey
        if status == errSecSuccess, let item = keyItem {
            key = item as! SecKey
        } else if status == errSecItemNotFound {
            var error: Unmanaged<CFError>?
            let attributes: [String: Any] = [
                kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                kSecAttrKeySizeInBits as String: 2048,
                kSecPrivateKeyAttrs as String: [
                    kSecAttrIsPermanent as String: true,
                    kSecAttrApplicationTag as String: Self.tag,
                    kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
                ]
            ]
            guard let generated = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
                throw RemoteError.message("تعذّر إنشاء هوية الاتصال: \(String(describing: error))")
            }
            key = generated
        } else { throw RemoteError.message("تعذّر فتح Keychain (\(status)). افتح قفل الآيفون وأعد المحاولة.") }
        guard let pub = SecKeyCopyPublicKey(key) else { throw WireError.malformed }
        publicKey = pub

        let certQuery: [String: Any] = [kSecClass as String: kSecClassCertificate,
            kSecAttrLabel as String: Self.certificateLabel, kSecReturnRef as String: true]
        var certItem: CFTypeRef?
        let certStatus = SecItemCopyMatching(certQuery as CFDictionary, &certItem)
        let certificate: SecCertificate
        if certStatus == errSecSuccess, let item = certItem {
            certificate = item as! SecCertificate
        } else if certStatus == errSecItemNotFound {
            let data = try Self.makeCertificate(key, pub)
            guard let cert = SecCertificateCreateWithData(nil, data as CFData) else { throw WireError.malformed }
            let addStatus = SecItemAdd([kSecClass as String: kSecClassCertificate,
                kSecValueRef as String: cert, kSecAttrLabel as String: Self.certificateLabel,
                kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly] as CFDictionary, nil)
            guard addStatus == errSecSuccess else { throw RemoteError.message("تعذّر حفظ الشهادة (\(addStatus)).") }
            certificate = cert
        } else { throw RemoteError.message("تعذّر قراءة الشهادة (\(certStatus)).") }

        var items: CFTypeRef?
        let identityStatus = SecItemCopyMatching([
            kSecClass as String: kSecClassIdentity, kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ] as CFDictionary, &items)
        guard identityStatus == errSecSuccess, let identities = items as? [SecIdentity],
              let match = identities.first(where: { candidate in
                  var cert: SecCertificate?
                  return SecIdentityCopyCertificate(candidate, &cert) == errSecSuccess &&
                      cert.map { SecCertificateCopyData($0) as Data == SecCertificateCopyData(certificate) as Data } == true
              }) else { throw RemoteError.message("تعذّر العثور على هوية TLS في Keychain.") }
        identity = match
    }

    private static func makeCertificate(_ key: SecKey, _ pub: SecKey) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let publicDER = SecKeyCopyExternalRepresentation(pub, &error) as Data? else { throw WireError.malformed }
        let name = DER.sequence(DER.value(0x31, DER.sequence(
            Data([6, 3, 0x55, 4, 3]) + DER.value(0x0c, Data("MiBox Remote iPhone".utf8)))))
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyyyMMddHHmmss'Z'"
        let validity = DER.sequence(
            DER.value(0x18, Data(formatter.string(from: Date().addingTimeInterval(-86400)).utf8)) +
            DER.value(0x18, Data(formatter.string(from: Date().addingTimeInterval(10 * 365 * 86400)).utf8)))
        var serial = [UInt8](repeating: 0, count: 16)
        guard SecRandomCopyBytes(kSecRandomDefault, serial.count, &serial) == errSecSuccess else { throw WireError.malformed }
        let tbs = DER.sequence(DER.value(0xa0, DER.integer(Data([2]))) +
            DER.integer(Data(serial)) + DER.sha256RSA + name + validity + name +
            DER.sequence(DER.rsa + DER.value(3, Data([0]) + publicDER)))
        guard let signature = SecKeyCreateSignature(key, .rsaSignatureMessagePKCS1v15SHA256,
                                                    tbs as CFData, &error) as Data? else { throw WireError.malformed }
        return DER.sequence(tbs + DER.sha256RSA + DER.value(3, Data([0]) + signature))
    }
}
