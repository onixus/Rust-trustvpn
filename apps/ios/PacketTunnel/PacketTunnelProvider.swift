import NetworkExtension

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let queue = DispatchQueue(label: "org.rtrusttunnel.packet-flow")
    private var timer: DispatchSourceTimer?
    private var generation: UInt64 = 0
    private var completion: ((Error?) -> Void)?
    private var lastReportedState: UInt8?
    private var deadline = Date.distantPast

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        queue.async {
            self.generation &+= 1
            let token = self.generation
            self.completion = completionHandler
            do {
                let plan = try ProfilePlan.parse(ProfileVault.load())
                let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
                settings.mtu = NSNumber(value: plan.mtu ?? 1500)
                let ipv4 = NEIPv4Settings(addresses: ["169.254.254.2"], subnetMasks: ["255.255.255.255"])
                ipv4.includedRoutes = try (plan.routes ?? []).filter { !$0.contains(":") }.map { route in
                    let parts = route.split(separator: "/")
                    guard parts.count == 2, let prefix = Int(parts[1]), (0...32).contains(prefix) else { throw AppError.message("Invalid route") }
                    let mask: UInt32 = prefix == 0 ? 0 : UInt32.max << (32 - prefix)
                    let text = [24,16,8,0].map { String((mask >> $0) & 255) }.joined(separator: ".")
                    return NEIPv4Route(destinationAddress: String(parts[0]), subnetMask: text)
                }
                settings.ipv4Settings = ipv4
                // Capture IPv6 even when the endpoint is IPv4-only. The Rust
                // data plane refuses it locally; never leave it on the physical path.
                let ipv6 = NEIPv6Settings(addresses: ["fd00:5254::2"], networkPrefixLengths: [128])
                ipv6.includedRoutes = plan.ipv6 == false ? [.default()] : try (plan.routes ?? []).filter { $0.contains(":") }.map { route in
                    let parts = route.split(separator: "/")
                    guard parts.count == 2, let prefix = Int(parts[1]), (0...128).contains(prefix) else { throw AppError.message("Invalid route") }
                    return NEIPv6Route(destinationAddress: String(parts[0]), networkPrefixLength: NSNumber(value: prefix))
                }
                settings.ipv6Settings = ipv6
                let dns = NEDNSSettings(servers: plan.dns!)
                dns.matchDomains = [""]
                settings.dnsSettings = dns
                self.setTunnelNetworkSettings(settings) { error in
                    self.queue.async {
                        guard token == self.generation else { return }
                        if error != nil { self.failStart(); return }
                        let data = Data(plan.profile!.utf8)
                        let started = data.withUnsafeBytes { bytes in
                            rtrust_ios_start(bytes.bindMemory(to: UInt8.self).baseAddress, data.count)
                        }
                        guard started else { self.failStart(); return }
                        self.deadline = Date().addingTimeInterval(30)
                        self.read(token)
                        let timer = DispatchSource.makeTimerSource(queue: self.queue)
                        timer.schedule(deadline: .now(), repeating: .milliseconds(10))
                        timer.setEventHandler { [weak self] in self?.pump(token) }
                        self.timer = timer
                        timer.resume()
                    }
                }
            } catch { self.failStart() }
        }
    }
    private func failStart() {
        generation &+= 1
        timer?.cancel(); timer = nil
        rtrust_ios_stop()
        WidgetState.update(.disconnected)
        let handler = completion; completion = nil
        handler?(AppError.message("Cannot establish secure tunnel. Check profile and endpoint."))
    }
    private func read(_ token: UInt64) {
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self else { return }
            self.queue.async {
                guard token == self.generation else { return }
                for packet in packets {
                    packet.withUnsafeBytes { bytes in
                        _ = rtrust_ios_push(bytes.bindMemory(to: UInt8.self).baseAddress, packet.count)
                    }
                }
                self.read(token)
            }
        }
    }
    private func pump(_ token: UInt64) {
        guard token == generation else { return }
        let state = rtrust_ios_status()
        if state != lastReportedState {
            lastReportedState = state
            WidgetState.update(state == 2 ? .connected : .reasserting)
        }
        if completion != nil {
            if state == 2 {
                let handler = completion; completion = nil; handler?(nil)
            } else if state == 4 || Date() >= deadline { failStart(); return }
        } else {
            // Keep routes installed after a transport failure. Stop is explicit.
            reasserting = state != 2
        }
        var buffer = [UInt8](repeating: 0, count: 65535)
        var packets: [Data] = []
        var families: [NSNumber] = []
        for _ in 0..<64 {
            let length = buffer.withUnsafeMutableBufferPointer { rtrust_ios_pop($0.baseAddress, $0.count) }
            if length == 0 { break }
            packets.append(Data(buffer.prefix(length)))
            families.append(NSNumber(value: buffer[0] >> 4 == 6 ? AF_INET6 : AF_INET))
        }
        if !packets.isEmpty { _ = packetFlow.writePackets(packets, withProtocols: families) }
    }
    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        queue.async {
            self.generation &+= 1
            self.timer?.cancel(); self.timer = nil
            rtrust_ios_stop()
            let start = self.completion; self.completion = nil
            start?(AppError.message("Connection cancelled"))
            WidgetState.update(.disconnected)
            self.reasserting = false
            completionHandler()
        }
    }
}
