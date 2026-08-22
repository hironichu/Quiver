import Testing
import Foundation
import QUIC
import QUICCore
import QUICRecovery

@Suite("QUIC Configuration Tests")
struct QUICConfigurationTests {

    @Test("Default configuration")
    func defaultConfig() {
        let config = QUICConfiguration()

        #expect(config.maxIdleTimeout == .seconds(30))
        #expect(config.maxUDPPayloadSize == 1200)
        #expect(config.initialMaxData == 10_000_000)
        #expect(config.initialMaxStreamsBidi == 100)
        #expect(config.alpn == ["h3"])
    }

    @Test("Transport parameters from configuration")
    func transportParameters() throws {
        let config = QUICConfiguration()
        let scid = try #require(ConnectionID.random(length: 8))

        let params = TransportParameters(from: config, sourceConnectionID: scid)

        #expect(params.initialMaxData == config.initialMaxData)
        #expect(params.initialMaxStreamsBidi == config.initialMaxStreamsBidi)
        #expect(params.initialSourceConnectionID == scid)
    }

    @Test("Congestion controller factory can be injected")
    func congestionControllerFactoryInjection() {
        var config = QUICConfiguration()
        config.congestionControllerFactory = BBRFactory()

        let controller = config.congestionControllerFactory.makeCongestionController(maxDatagramSize: 1200)

        #expect(controller is BBRCongestionController)
        #expect(String(describing: controller).contains("BBR"))
    }
}
