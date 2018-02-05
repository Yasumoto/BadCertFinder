import Foundation
import Menkyo

struct CertError: Error {}

var args = CommandLine.arguments

if (args.contains("--help") || args.contains("-h")) {
    print("BadCertFinder [-c|--count] <directory_to_search>")
    print("Built from https://github.com/Yasumoto/BadCertFinder")
    exit(1)
}

var count = false
if (args.contains("-c") || args.contains("--count")) {
    count = true
    args = args.filter({ arg in arg != "-c" && arg != "--count" })
}

if (args.count != 2) {
    print("Please pass one directory name to parse certificates!")
    exit(1)
}

var expiring = [String:Certificate]()
let infos = enumerateCertificates(
    baseDirectory: args[1])
let formatter = DateFormatter()
guard let soon =  Calendar.current.date(byAdding: .month, value: 1, to: Date()) else { throw CertError() }
for (pathName, info) in infos {
    if let expirationDate = info.notAfter {
        if expirationDate < soon {
            expiring[pathName] = info
        }
    }
}

// WoSign
// https://security.googleblog.com/2016/10/distrusting-wosign-and-startcom.html
// https://support.apple.com/en-us/HT204132

// Symantec
// https://security.googleblog.com/2017/09/chromes-plan-to-distrust-symantec.html
let badIssuers = ["startcom", "startssl", "geotrust", "symantec"]
var reissues = [String:Certificate]()
for (pathName, info) in infos {
    if let issuer = info.issuer, let issuerCN = issuer[.commonName] {
        for badIssuer in badIssuers {
            if issuerCN.lowercased().contains(badIssuer) {
                reissues[pathName] = info
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
    if expiring.count == 1 {
        print("\(expiring.count) cert expires soon.")
    } else {
        print("\(expiring.count) certs expiring soon.")
    }
    if !count {
        for (path, _) in expiring {
            print(path)
        }
    }
}

if reissues.count > 0 {
    if reissues.count == 1 {
        print("\(reissues.count) cert should be replaced before its CA is distrusted.")
    } else {
        print("\(reissues.count) certs should be replaced before their CA is distrusted.")
    }
    if !count {
        for (path, info) in reissues {
            print(path)
            if let names = info.alternateNames {
                print("\t\(names.joined(separator: ", "))\n")
            }
        }
    }
}
