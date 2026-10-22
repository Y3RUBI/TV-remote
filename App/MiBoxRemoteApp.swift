import SwiftUI

@main
struct MiBoxRemoteApp: App {
    var body: some Scene {
        WindowGroup {
            RemoteView()
                .environment(\.layoutDirection, .rightToLeft)
                .preferredColorScheme(.dark)
        }
    }
}

struct RemoteView: View {
    @StateObject private var remote = RemoteModel()
    @StateObject private var discovery = Discovery()
    @Environment(\.scenePhase) private var scenePhase
    @State private var resume = false
    private let orange = Color(red: 1, green: 0.43, blue: 0.13)

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 22) {
                    header
                    connectionPanel
                    if remote.needsCode { pairingPanel }
                    controls
                    Text("اتصال مباشر عبر شبكتك المحلية • بدون اشتراك")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                .padding(20)
            }
            .background(Color(red: 0.045, green: 0.055, blue: 0.075))
            .navigationTitle("ريموت شاومي")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button { discovery.search() } label: { Image(systemName: "arrow.clockwise") }
                        .accessibilityLabel("تحديث قائمة الأجهزة")
                }
            }
            .tint(orange)
            .alert("تنبيه", isPresented: Binding(get: { remote.error != nil }, set: { if !$0 { remote.error = nil } })) {
                Button("حسنًا") { remote.error = nil }
            } message: { Text(remote.error ?? "") }
            .onAppear { discovery.search() }
            .onChange(of: scenePhase) { phase in
                if phase == .background {
                    resume = remote.connected
                    remote.stop()
                    discovery.stop()
                } else if phase == .active {
                    discovery.search()
                    if resume { resume = false; remote.connect() }
                }
            }
        }
    }

    private var header: some View {
        HStack(spacing: 14) {
            Image(systemName: "appletvremote.gen4.fill")
                .font(.system(size: 36)).foregroundStyle(orange)
                .frame(width: 70, height: 70).background(orange.opacity(0.13), in: RoundedRectangle(cornerRadius: 22))
            VStack(alignment: .leading, spacing: 7) {
                Text("Xiaomi TV Box").font(.title2.bold())
                HStack(spacing: 6) {
                    Circle().fill(remote.connected ? .green : .gray).frame(width: 7, height: 7)
                    Text(remote.status).font(.caption).foregroundStyle(.secondary)
                }
            }
            Spacer(minLength: 0)
        }
    }

    private var connectionPanel: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("الجهاز", systemImage: "wifi").font(.headline)
            if !remote.connected && !remote.busy {
                Text(discovery.message).font(.caption).foregroundStyle(.secondary)
                ForEach(discovery.devices) { device in
                    Button {
                        remote.host = device.host
                        remote.connect()
                    } label: {
                        HStack {
                            Image(systemName: "tv")
                            Text(device.name).lineLimit(1)
                            Spacer()
                            Image(systemName: "chevron.left")
                        }.padding(12).background(.white.opacity(0.05), in: RoundedRectangle(cornerRadius: 12))
                    }
                }
            }
            TextField("عنوان IP مثل 192.168.1.20", text: $remote.host)
                .keyboardType(.asciiCapable).textInputAutocapitalization(.never).autocorrectionDisabled()
                .environment(\.layoutDirection, .leftToRight)
                .padding(12).background(.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 12))
                .disabled(remote.busy || remote.connected)
                .accessibilityLabel("عنوان IP لجهاز التلفزيون")
            HStack(spacing: 12) {
                if remote.connected || remote.busy {
                    Button(remote.busy ? "إلغاء الاتصال" : "قطع الاتصال") { resume = false; remote.stop() }
                        .buttonStyle(.bordered)
                    if remote.busy { ProgressView().controlSize(.small) }
                } else {
                    Button("اتصال") { remote.connect() }.buttonStyle(.borderedProminent)
                    Button("إعادة الاقتران") { remote.connect(pair: true) }.buttonStyle(.bordered)
                }
            }
            if !remote.connected {
                Text("شغّل الجهاز والتلفزيون، ووصل الآيفون بنفس الشبكة. اسمح للتطبيق بالوصول إلى الشبكة المحلية.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .padding(18).frame(maxWidth: .infinity, alignment: .leading)
        .background(.white.opacity(0.045), in: RoundedRectangle(cornerRadius: 22))
    }

    private var pairingPanel: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("رمز الاقتران", systemImage: "lock.shield").font(.headline)
            Text("أدخل الخانات الست الظاهرة على شاشة التلفزيون.")
                .font(.caption).foregroundStyle(.secondary)
            TextField("A1B2C3", text: $remote.code)
                .font(.system(.title2, design: .monospaced)).multilineTextAlignment(.center)
                .textInputAutocapitalization(.characters).autocorrectionDisabled().keyboardType(.asciiCapable)
                .environment(\.layoutDirection, .leftToRight)
                .padding(12).background(.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 12))
                .onChange(of: remote.code) { value in
                    let filtered = String(value.uppercased().filter { "0123456789ABCDEF".contains($0) }.prefix(6))
                    if value != filtered { remote.code = filtered }
                }
            Button("تأكيد الاقتران") { remote.submitCode() }
                .buttonStyle(.borderedProminent).disabled(remote.code.count != 6)
        }.padding(18).background(orange.opacity(0.08), in: RoundedRectangle(cornerRadius: 22))
    }

    private var controls: some View {
        VStack(spacing: 20) {
            HStack {
                key("التشغيل / الاستعداد", "power", 26)
                Spacer()
                key("كتم الصوت", "speaker.slash.fill", 164)
            }
            VStack(spacing: 10) {
                key("أعلى", "chevron.up", 19)
                HStack(spacing: 16) {
                    key("يسار", "chevron.left", 21)
                    Button { tap(23) } label: {
                        Text("OK").font(.title2.bold()).frame(width: 88, height: 88)
                            .background(orange, in: Circle()).foregroundStyle(.white)
                    }.accessibilityLabel("تأكيد الاختيار")
                    key("يمين", "chevron.right", 22)
                }
                key("أسفل", "chevron.down", 20)
            }
            .environment(\.layoutDirection, .leftToRight)
            HStack {
                key("رجوع", "arrow.uturn.backward", 4)
                Spacer()
                key("الرئيسية", "house.fill", 3)
                Spacer()
                key("القائمة", "line.3.horizontal", 82)
            }
            HStack(spacing: 12) {
                key("خفض الصوت", "speaker.minus.fill", 25, wide: true)
                key("تشغيل / إيقاف مؤقت", "playpause.fill", 85, wide: true)
                key("رفع الصوت", "speaker.plus.fill", 24, wide: true)
            }
            Text("تشغيل الجهاز من وضع الاستعداد يعتمد على دعم الشبكة أثناء السكون. التحكم بالصوت يعتمد على إعدادات الجهاز وHDMI-CEC.")
                .font(.caption2).foregroundStyle(.secondary).multilineTextAlignment(.center)
        }
        .disabled(!remote.connected).opacity(remote.connected ? 1 : 0.4)
    }

    private func key(_ name: String, _ symbol: String, _ code: UInt64, wide: Bool = false) -> some View {
        Button { tap(code) } label: {
            Image(systemName: symbol).font(.system(size: 22, weight: .semibold))
                .frame(maxWidth: wide ? .infinity : nil)
                .frame(width: wide ? nil : 64, height: 58)
                .background(.white.opacity(0.07), in: RoundedRectangle(cornerRadius: 18))
                .foregroundStyle(.white)
        }.accessibilityLabel(name)
    }
    private func tap(_ code: UInt64) {
        UIImpactFeedbackGenerator(style: .light).impactOccurred()
        remote.key(code)
    }
}
