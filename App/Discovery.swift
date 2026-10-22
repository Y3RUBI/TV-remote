import Foundation
import Combine

struct TVDevice: Identifiable {
    let id: String
    let name: String
    let host: String
}

final class Discovery: NSObject, ObservableObject, NetServiceBrowserDelegate, NetServiceDelegate {
    @Published var devices: [TVDevice] = []
    @Published var message = "جارٍ البحث على الشبكة المحلية…"
    private let browser = NetServiceBrowser()
    private var services: [NetService] = []
    private var timer: Timer?
    override init() { super.init(); browser.delegate = self }
    func search() {
        stop()
        devices = []
        services = []
        message = "جارٍ البحث على الشبكة المحلية…"
        browser.searchForServices(ofType: "_androidtvremote2._tcp.", inDomain: "local.")
        timer = Timer.scheduledTimer(withTimeInterval: 12, repeats: false) { [weak self] _ in
            guard let self else { return }
            self.message = self.devices.isEmpty ? "لم يظهر جهاز. يمكنك إدخال عنوان IP يدويًا." : "اختر جهاز Xiaomi الخاص بك"
        }
    }
    func stop() {
        timer?.invalidate()
        browser.stop()
        for service in services { service.stop() }
    }
    func netServiceBrowser(_ browser: NetServiceBrowser, didFind service: NetService, moreComing: Bool) {
        services.append(service)
        service.delegate = self
        service.resolve(withTimeout: 8)
    }
    func netServiceDidResolveAddress(_ sender: NetService) {
        guard let hostname = sender.hostName else { return }
        let id = sender.name + "." + sender.type + sender.domain
        devices.removeAll { $0.id == id }
        devices.append(TVDevice(id: id, name: sender.name, host: hostname))
        devices.sort { $0.name < $1.name }
        message = "اختر جهاز Xiaomi الخاص بك"
    }
    func netServiceBrowser(_ browser: NetServiceBrowser, didRemove service: NetService, moreComing: Bool) {
        devices.removeAll { $0.id == service.name + "." + service.type + service.domain }
    }
    func netServiceBrowser(_ browser: NetServiceBrowser, didNotSearch errorDict: [String: NSNumber]) {
        message = "تعذّر البحث. اسمح بالوصول إلى الشبكة المحلية في إعدادات الآيفون، أو أدخل IP."
    }
}
