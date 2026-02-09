// Silences verbose logging during test execution.
//
// XCTest classes are processed before Swift Testing suites.
// The `_AAA_` prefix ensures this class sorts first alphabetically,
// so its `setUp()` runs before any other test class in this target.
//
// `LoggingSystem.bootstrap` is process-wide, so this single call
// silences all `Logger` instances (webtransport.*, http3.*, etc.)
// across both XCTest and Swift Testing tests in the same process.

import XCTest
import Logging

final class _AAA_TestLoggingBootstrap: XCTestCase {
    override class func setUp() {
        super.setUp()
        LoggingSystem.bootstrap { label in
            var handler = StreamLogHandler.standardError(label: label)
            handler.logLevel = .critical
            return handler
        }
    }

    func testLoggingBootstrapped() {
        // Ensures this class is discovered by XCTest
    }
}