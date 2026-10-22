import Foundation
import Network
import Security

/// All channel callbacks and public operations run on the main queue.
final class TLSChannel {
    private let connection: NWConnection
    private var frames = FrameBuffer()
    var onReady: (() -> Void)?
    var onMessage: ((Data) -> Void)?
    var onError: ((String) -> Void)?
    private var closed = false

    init(host: String, port: UInt16, identity: SecIdentity,
         verify: @escaping (SecTrust) -> Bool) throws {
        guard let identity = sec_identity_create(identity) else { throw WireError.malformed }
        let tls = NWProtocolTLS.Options()
        sec_protocol_options_set_local_identity(tls.securityProtocolOptions, identity)
        sec_protocol_options_set_min_tls_protocol_version(tls.securityProtocolOptions, .TLSv12)
        sec_protocol_options_set_verify_block(tls.securityProtocolOptions, { _, trust, complete in
            complete(verify(sec_trust_copy_ref(trust).takeRetainedValue()))
        }, .main)
        let tcp = NWProtocolTCP.Options()
        tcp.connectionTimeout = 12
        connection = NWConnection(host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: port)!,
                                  using: NWParameters(tls: tls, tcp: tcp))
    }
    func start() {
        connection.stateUpdateHandler = { [weak self] state in
            guard let self, !self.closed else { return }
            switch state {
            case .ready: self.onReady?(); self.receive()
            case .failed(let error), .waiting(let error): self.fail(error.localizedDescription)
            default: break
            }
        }
        connection.start(queue: .main)
    }
    func send(_ body: Data) {
        guard !closed else { return }
        connection.send(content: PB.varint(UInt64(body.count)) + body,
                        completion: .contentProcessed { [weak self] error in
            if let error { self?.fail(error.localizedDescription) }
        })
    }
    func close() {
        closed = true
        connection.stateUpdateHandler = nil
        connection.cancel()
    }
    private func receive() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, complete, error in
            guard let self, !self.closed else { return }
            do {
                if let data {
                    for frame in try self.frames.append(data) {
                        guard !self.closed else { return }
                        self.onMessage?(frame)
                    }
                }
                guard !self.closed else { return }
                if let error { self.fail(error.localizedDescription) }
                else if complete { self.fail("انقطع الاتصال بالجهاز.") }
                else { self.receive() }
            } catch { self.fail("وصلت رسالة شبكة غير صالحة.") }
        }
    }
    private func fail(_ text: String) {
        guard !closed else { return }
        close()
        onError?(text)
    }
    deinit { connection.cancel() }
}
