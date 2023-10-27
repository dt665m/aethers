import aethers 

initLogger()

let provider_url = "https://aminoxtestnet.node.alphacarbon.network/"
let provider = try! providerFromUrl(url: provider_url)
let wallet = try! fromMnemonic(mnemonic: "inspire joke young brother either erase pole poverty talk drop dilemma wink", password: "1234", chainId: 13370 )
let address = wallet.requestAccounts()
let nftContractAddress = "0x805c48ab8dBcE5bF1BdF2C8Dfddef6EE9b412241"
let bridgeContractAddress = "0xffffffff8d2ee523a2206206994597c13d831ec7"
print("test user address: ", address)

func testDecryptedAddress() {
    let encrypted = try! wallet.encryptJson()
    print("encrypted wallet:\n", encrypted)
    let decryptedWallet = try! decryptJson(encrypted: encrypted, password: "1234", chainId: 13370)
    let decryptedAddress = decryptedWallet.requestAccounts()
    assert(address == decryptedAddress)
}

func testNewWallet() {
    let newWallet = Wallet(password: "1234", chainId: 13370)
    let phrase = try! newWallet.recoverPhrase(password: "1234")
    print("new wallet phrase:", phrase)
    let address = newWallet.requestAccounts()
    print("new wallet address:", address)
}

func testNft() {
    let price = try! wallet.nftCurrentPrice(provider: provider, contract: nftContractAddress);
    assert(10_000_000_000_000_000 == price)
    let totalSupply = try! wallet.nftTotalSupply(provider: provider, contract: nftContractAddress);
    print("NFT total supply:", totalSupply)
    let txHash = try! wallet.nftMint(provider: provider, contract: nftContractAddress, to: "0xce381ddac7207129d81431604332a7c016492aa6", value: 10_000_000_000_000_000);
    print("mint tx hash:", txHash)
}

func testTransferBridgeOut() {
    let txHash = try! wallet.transferBridgeOut(provider: provider, contract: bridgeContractAddress, to: "0x46594bb57b9CcA5a4B2c968E3A4bAFb258587308", value: 100, chainId: 0, chainType: 7);
    print("transferBridgeOut tx hash::", txHash)
}

print("===Test New Wallet===\n")
testNewWallet()

//#NOTE Ensure that the account has enough ACT and USDT.
// print("===Test Decrypted Address===\n")
// testDecryptedAddress()
// print("===Test NFT===\n")
// testNft()
// print("===Test Transfer Bridge Out===\n")
// testTransferBridgeOut()