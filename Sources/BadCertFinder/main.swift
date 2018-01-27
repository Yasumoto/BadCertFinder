import Foundation
import Menkyo

struct CertError: Error {}

if (CommandLine.arguments.count != 2) {
    print("Please pass one directory name to parse certificates!")
    exit(1)
}

var expiring = Set<String>()
let infos = enumerateCertificates(
    baseDirectory: CommandLine.arguments[1])
let formatter = DateFormatter()
guard let soon =  Calendar.current.date(byAdding: .month, value: 1, to: Date()) else { throw CertError() }
for (pathName, info) in infos {
    if let expirationDate = info.notAfter {
        if expirationDate < soon {
            expiring.insert(pathName)
        }
    }
}

let badIssuers = ["startcom", "startssl", "geotrust"]
var reissues = Set<String>()
for (pathName, info) in infos {
    if let issuer = info.issuer {
        if let issuerCN = issuer[.commonName] {
            for badIssuer in badIssuers {
                if issuerCN.lowercased().contains(badIssuer) {
                    reissues.insert(pathName)
                }
            }
        }
    } else if let issuers = info.issuerAltName {
        for issuer in issuers {
            for badIssuer in badIssuers {
                if issuer.lowercased().contains(badIssuer) {
                    reissues.insert(pathName)
                }
            }
        }
    }
}

print("These certs expiring soon:")
for path in expiring {
    print(path)
}

print("These certs should be replaced before their CA is distrusted:")
for path in reissues {
    print(path)
}
