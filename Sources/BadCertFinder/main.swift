import Foundation
import Menkyo

struct CertError: Error {}

if (CommandLine.arguments.count != 2) {
    print("Please pass one directory name to parse certificates!")
    exit(1)
}

var expiring = [String:Certificate]()
let infos = enumerateCertificates(
    baseDirectory: CommandLine.arguments[1])
let formatter = DateFormatter()
guard let soon =  Calendar.current.date(byAdding: .month, value: 1, to: Date()) else { throw CertError() }
for (pathName, info) in infos {
    if let expirationDate = info.notAfter {
        if expirationDate < soon {
            expiring[pathName] = info
        }
    }
}

let badIssuers = ["startcom", "startssl", "geotrust"]
var reissues = [String:Certificate]()
for (pathName, info) in infos {
    if let issuer = info.issuer {
        if let issuerCN = issuer[.commonName] {
            for badIssuer in badIssuers {
                if issuerCN.lowercased().contains(badIssuer) {
                    reissues[pathName] = info
                }
            }
        }
    } else if let issuers = info.issuerAltName {
        for issuer in issuers {
            for badIssuer in badIssuers {
                if issuer.lowercased().contains(badIssuer) {
                    reissues[pathName] = info
                }
            }
        }
    }
}

if expiring.count > 0 {
    print("These certs expiring soon:")
    for (path, info) in expiring {
        print(path)
    }
}

if reissues.count > 0 {
    print("These certs should be replaced before their CA is distrusted:")
    for (path, info) in reissues {
        print(path)
        if let names = info.alternateNames {
            print("\t\(names.joined(separator: ", "))\n")
        }
    }
}
