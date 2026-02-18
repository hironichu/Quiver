import XCTest

@testable import QUICCrypto

final class PEMLoaderTests: XCTestCase {

    func testLoadCertificateChain() throws {
        // Create a temporary file with multiple certificates
        let cert1 = """
            -----BEGIN CERTIFICATE-----
            MIICjTCCAjSgAwIBAgIBADAKBggqhkjOPQQDAjB9MQswCQYDVQQGEwJVUzELMAkG
            A1UECAwCQ0ExEzARBgNVBAcMCnlvdXIgQ2l0eTEZMBcGA1UECgwQeW91ciBPcmdh
            bml6YXRpb24xGTAXBgNVBAsMEHlvdXIgT3JnYW5pemF0aW9uMRgwFgYDVQQDDA95
            b3VyIERvbWFpbiBOYW1lMB4XDTI0MDIxMjE4NTcyMVoXDTI1MDIxMTE4NTcyMVow
            fTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRMwEQYDVQQHDAp5b3VyIENpdHkx
            GTAXBgNVBAoMEHlvdXIgT3JnYW5pemF0aW9uMRkwFwYDVQQLDBB5b3VyIE9yZ2Fu
            aXphdGlvbjEYMBYGA1UEAwwPeW91ciBEb21haW4gTmFtZTBZMBMGByqGSM49AgEG
            CCqGSM49AwEHA0IABNZ1c+0d/4qI5yX8s+8+8+8+8+8+8+8+8+8+8+8+8+8+8+8+
            8+8+8+8+8+8+8+8+8+8+8+8+8+8+8+8+8+8+8+mjgbQwgbEwDAYDVR0TAQH/BAIw
            ADAfBgNVHSMEGDAWgBQF/5K8r/5K8r/5K8r/5K8r/5K8r/5K8r/5K8r/5K8r/5K8
            DTAdBgNVHQ4EFgQUBf+SvK/+SvK/+SvK/+SvK/+SvK/+SvK/+SvK/+SvK/+SvK/5
            K8r/5K8r/5K8r/5K8r/5K8r/5K8r/5K8MA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUE
            FjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwCgYIKoZIzj0EAwIDSAAwRQIhAI9/1/1/
            1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/AiB/1/1/1/1/1/1/1/1/1/1/1/1/
            1/1/1/1/1/1/1/1/1w==
            -----END CERTIFICATE-----
            """

        // Just a dummy second cert block for testing parsing logic (content doesn't need to be valid DER for this test, just base64)
        let cert2 = """
            -----BEGIN CERTIFICATE-----
            MIICjTCCAjSgAwIBAgIBADAKBggqhkjOPQQDAjB9MQswCQYDVQQGEwJVUzELMAkG
            A1UECAwCQ0ExEzARBgNVBAcMCnlvdXIgQ2l0eTEZMBcGA1UECgwQeW91ciBPcmdh
            bml6YXRpb24xGTAXBgNVBAsMEHlvdXIgT3JnYW5pemF0aW9uMRgwFgYDVQQDDA95
            b3VyIERvbWFpbiBOYW1lMB4XDTI0MDIxMjE4NTcyMVoXDTI1MDIxMTE4NTcyMVow
            fTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRMwEQYDVQQHDAp5b3VyIENpdHkx
            GTAXBgNVBAoMEHlvdXIgT3JnYW5pemF0aW9uMRkwFwYDVQQLDBB5b3VyIE9yZ2Fu
            aXphdGlvbjEYMBYGA1UEAwwPeW91ciBEb21haW4gTmFtZTBZMBMGByqGSM49AgEG
            CCqGSM49AwEHA0IABNZ1c+0d/4qI5yX8s+8+8+8+8+8+8+8+8+8+8+8+8+8+8+8+
            8+8+8+8+8+8+8+8+8+8+8+8+8+8+8+8+8+8+mjgbQwgbEwDAYDVR0TAQH/BAIw
            ADAfBgNVHSMEGDAWgBQF/5K8r/5K8r/5K8r/5K8r/5K8r/5K8r/5K8r/5K8r/5K8
            DTAdBgNVHQ4EFgQUBf+SvK/+SvK/+SvK/+SvK/+SvK/+SvK/+SvK/+SvK/+SvK/5
            K8r/5K8r/5K8r/5K8r/5K8r/5K8r/5K8MA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUE
            FjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwCgYIKoZIzj0EAwIDSAAwRQIhAI9/1/1/
            1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/AiB/1/1/1/1/1/1/1/1/1/1/1/1/
            1/1/1/1/1/1/1/1/1w==
            -----END CERTIFICATE-----
            """

        let fileContent = cert1 + "\n" + cert2

        let tempURL = FileManager.default.temporaryDirectory.appendingPathComponent(
            "chain_test.pem")
        try fileContent.write(to: tempURL, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: tempURL) }

        let certs = try PEMLoader.loadCertificates(fromPath: tempURL.path)

        XCTAssertEqual(certs.count, 2, "Should have loaded 2 certificates")
    }
}
