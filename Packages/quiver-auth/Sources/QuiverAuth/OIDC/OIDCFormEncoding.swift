import Foundation

func oidcFormURLEncoded(_ pairs: [(String, String)]) -> String {
    pairs
        .map { "\(oidcURLEncode($0.0))=\(oidcURLEncode($0.1))" }
        .joined(separator: "&")
}

private func oidcURLEncode(_ value: String) -> String {
    var allowed = CharacterSet.urlQueryAllowed
    allowed.remove(charactersIn: ":#[]@!$&'()*+,;=")
    return value.addingPercentEncoding(withAllowedCharacters: allowed) ?? value
}
