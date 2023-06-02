import aethers 

initLogger()
let jsonString = "{\"crypto\":{\"cipher\":\"aes-128-ctr\",\"cipherparams\":{\"iv\":\"159f7792c62ffe92731a85d730c1613c\"},\"ciphertext\":\"3dd922c6248d07ab3fee4bd1b5d95b5e40e105eeace718355616af13f83e3e2817799379d9cd24aaf57e4c68a25e2133c62a28770856730095dbfce4d0d5d9d7841eee96776de62bfbabb610\",\"kdf\":\"scrypt\",\"kdfparams\":{\"dklen\":32,\"n\":8192,\"p\":1,\"r\":8,\"salt\":\"fc48d2e37f67b4d92c6427b3e9086ed6671dcd9dbe3dff406aec197693494506\"},\"mac\":\"2a606fb39e423c820440b7dd82ae24c477a6521d24d98f419013f1c47a916fbc\"},\"id\":\"0580948c-7ed5-4905-a045-7908971241f4\",\"version\":3}"
let escapedJsonString = jsonString.replacingOccurrences(of: "\"", with: "\\\"")
print(escapedJsonString)

let provider_url = "https://cloudflare-eth.com"
let provider = try! providerFromUrl(url: provider_url)
let wallet = Wallet(password: "1234")
let phrase = try! wallet.recoverPhrase(password: "1234")
print("new wallet phrase:", phrase)
let address = wallet.requestAccounts()
print("new wallet address:", address)
let encrypted = try! wallet.encryptJson()
print("encrypted wallet:\n", encrypted)
let decrypted_wallet = try! decryptJson(encrypted: encrypted, password: "1234")
let decrypted_address = decrypted_wallet.requestAccounts()
let decrypted_wallet2 = try! decryptJson(encrypted: jsonString, password: "123456")
assert(address == decrypted_address)

