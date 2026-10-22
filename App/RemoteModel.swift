import Foundation
import Security
import CryptoKit
import Combine

final class RemoteModel: ObservableObject {
    @Published var host = UserDefaults.standard.string(forKey: "lastHost") ?? ""
    @Published var status = "اختر جهازك لبدء التحكم"
    @Published var connected = false
    @Published var busy = false
    @Published var needsCode = false
    @Published var code = ""
    @Published var error: String?
    private var identity: ClientIdentity?
    private var channel: TLSChannel?
    private var timer: Timer?
    private var generation = UUID()
    private var serverKey: SecKey?
    private var serverCertificate: Data?
    private var expectedSecret: Data?
    private var activeHost = ""
    private var phase = 0
    private var features: UInt64 = 611 // ping, keys, power, volume, app links

    func connect(pair: Bool = false) {
        stop()
        let value = host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty, !value.contains("://"), !value.contains("/"), !value.contains(" ") else {
            error = "أدخل عنوان IP للجهاز فقط، مثل 192.168.1.20"; return
        }
        host = value
        activeHost = value
        let pairing = pair || savedPin == nil
        busy = true
        status = pairing ? "جارٍ طلب الاقتران من التلفزيون…" : "جارٍ الاتصال…"
        phase = 0
        expectedSecret = nil
        serverCertificate = nil
        serverKey = nil
        let token = generation
        do {
            if identity == nil { identity = try ClientIdentity() }
            guard let identity else { throw WireError.malformed }
            let pin = savedPin
            let transport = try TLSChannel(host: value, port: pairing ? 6467 : 6466, identity: identity.identity) { [weak self] trust in
                guard let self, self.generation == token,
                      let certificates = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
                      let certificate = certificates.first,
                      let key = SecTrustCopyKey(trust) else { return false }
                let data = SecCertificateCopyData(certificate) as Data
                if !pairing && pin != Self.fingerprint(data) { return false }
                self.serverKey = key
                self.serverCertificate = data
                return true
            }
            channel = transport
            transport.onReady = { [weak self] in
                guard let self, self.generation == token else { return }
                if pairing {
                    self.channel?.send(TVMessage.pairing(10, PB.string(1, "atvremote") + PB.string(2, "MiBox Remote iPhone")))
                }
            }
            transport.onMessage = { [weak self] data in
                guard let self, self.generation == token else { return }
                do {
                    if pairing { try self.pairingMessage(data) }
                    else { try self.remoteMessage(data) }
                } catch { self.fail("تعذّر فهم استجابة الجهاز. تحقق من تحديث Android TV Remote Service.") }
            }
            transport.onError = { [weak self] text in
                guard let self, self.generation == token else { return }
                self.fail("\(text)\nتأكد من الشبكة المحلية وعنوان الجهاز. جرّب «إعادة الاقتران» إذا تغيّرت هوية الجهاز.")
            }
            armTimeout(20)
            transport.start()
        } catch { fail(error.localizedDescription) }
    }

    private func pairingMessage(_ data: Data) throws {
        let fields = try PB.fields(data)
        guard fields.integer(2) == 200 else { fail("رفض الجهاز الاقتران. أعد المحاولة وتأكد من الرمز."); return }
        if fields.blob(11) != nil && phase == 0 {
            phase = 1
            channel?.send(TVMessage.pairing(20, PB.blob(1, TVMessage.encoding) + PB.int(3, 1)))
            armTimeout(20)
        } else if fields.blob(20) != nil && phase == 1 {
            phase = 2
            channel?.send(TVMessage.pairing(30, PB.blob(1, TVMessage.encoding) + PB.int(2, 1)))
            armTimeout(20)
        } else if fields.blob(31) != nil && phase == 2 {
            phase = 3
            needsCode = true
            code = ""
            status = "أدخل الرمز الظاهر على التلفزيون"
            armTimeout(120)
        } else if let ack = fields.blob(41), phase == 4 {
            guard let expectedSecret, try PB.fields(ack).blob(1) == expectedSecret,
                  let serverCertificate else { fail("لم تتطابق استجابة الاقتران مع الجهاز."); return }
            UserDefaults.standard.set(Self.fingerprint(serverCertificate), forKey: pinKey)
            UserDefaults.standard.set(activeHost, forKey: "lastHost")
            connect()
        } else { fail("وصلت استجابة اقتران غير متوقعة. أعد المحاولة.") }
    }

    func submitCode() {
        let input = code.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        guard phase == 3, input.count == 6, input.utf8.allSatisfy({ (48...57).contains($0) || (65...70).contains($0) }),
              let checksum = UInt8(input.prefix(2), radix: 16),
              let a = UInt8(input.dropFirst(2).prefix(2), radix: 16), let b = UInt8(input.suffix(2), radix: 16),
              let clientKey = identity?.publicKey, let serverKey else {
            error = "الرمز 6 خانات ويحتوي على الأرقام 0–9 والحروف A–F."; return
        }
        do {
            let client = try keyComponents(clientKey)
            let server = try keyComponents(serverKey)
            let secret = Data(SHA256.hash(data: client + server + Data([a, b])))
            guard secret.first == checksum else { error = "الرمز غير صحيح. تحقق من الشاشة وأعد إدخاله."; return }
            expectedSecret = secret
            phase = 4
            needsCode = false
            code = ""
            status = "جارٍ تأكيد الاقتران…"
            channel?.send(TVMessage.pairing(40, PB.blob(1, secret)))
            armTimeout(20)
        } catch { fail("تعذّر قراءة مفاتيح الجهاز. يجب أن يدعم Android TV Remote v2.") }
    }

    private func remoteMessage(_ data: Data) throws {
        let fields = try PB.fields(data)
        if let configure = fields.blob(1) {
            let config = try PB.fields(configure)
            features = config.integer(1) & 611
            guard features & 2 != 0 else { fail("هذا الجهاز لا يدعم أوامر الريموت المطلوبة."); return }
            let info = PB.string(1, "iPhone") + PB.string(2, "Apple") + PB.int(3, 1) +
                PB.string(4, "1") + PB.string(5, "app.miboxremote") + PB.string(6, "1.0.0")
            channel?.send(PB.blob(1, PB.int(1, features) + PB.blob(2, info)))
        }
        if fields.blob(2) != nil { channel?.send(PB.blob(2, PB.int(1, features))) }
        if let ping = fields.blob(8) {
            channel?.send(PB.blob(9, PB.int(1, try PB.fields(ping).integer(1))))
        }
        if fields.blob(40) != nil {
            timer?.invalidate()
            connected = true
            busy = false
            status = "متصل بجهاز Xiaomi TV Box"
            UserDefaults.standard.set(activeHost, forKey: "lastHost")
        }
        if fields.blob(3) != nil { fail("أبلغ الجهاز عن خطأ في جلسة التحكم. أعد الاتصال.") }
    }

    func key(_ value: UInt64) {
        guard connected else { return }
        channel?.send(TVMessage.key(value))
    }
    func stop() {
        generation = UUID()
        timer?.invalidate()
        channel?.close()
        channel = nil
        connected = false
        busy = false
        needsCode = false
        code = ""
        status = "غير متصل"
    }
    private var pinKey: String { "certificatePin." + activeHost }
    private var savedPin: String? { UserDefaults.standard.string(forKey: pinKey) }
    private static func fingerprint(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
    private func keyComponents(_ key: SecKey) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let bytes = SecKeyCopyExternalRepresentation(key, &error) as Data? else { throw WireError.malformed }
        return try DER.rsaComponents(bytes)
    }
    private func armTimeout(_ seconds: Double) {
        timer?.invalidate()
        timer = Timer.scheduledTimer(withTimeInterval: seconds, repeats: false) { [weak self] _ in
            self?.fail("انتهت مهلة الاتصال. تحقق من تشغيل الجهاز واتصاله بنفس شبكة Wi-Fi، ثم أعد المحاولة.")
        }
    }
    private func fail(_ text: String) { stop(); error = text }
}
