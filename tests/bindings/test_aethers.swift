import aethers 

initLogger()

let provider_url = "https://cloudflare-eth.com"
let provider = try! providerFromUrl(url: provider_url)
let wallet = Wallet(password: "1234", chainId: 88888)
let phrase = try! wallet.recoverPhrase(password: "1234")
print("new wallet phrase:", phrase)
let address = wallet.requestAccounts()
print("new wallet address:", address)
let encrypted = try! wallet.encryptJson()
print("encrypted wallet:\n", encrypted)
let decrypted_wallet = try! decryptJson(encrypted: encrypted, password: "1234", chainId: 88888)
let decrypted_address = decrypted_wallet.requestAccounts()
assert(address == decrypted_address)

