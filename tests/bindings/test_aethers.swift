import aethers 

initLogger()

let provider_url = "https://aminoxtestnet.node.alphacarbon.network/"
let provider = try! providerFromUrl(url: provider_url)
let wallet = try! fromMnemonic(mnemonic: "inspire joke young brother either erase pole poverty talk drop dilemma wink", password: "1234", chainId: 13370 )
let address = wallet.requestAccounts()
let nftContractAddress = "0x805c48ab8dBcE5bF1BdF2C8Dfddef6EE9b412241"
let bridgeContractAddress = "0xffffffff8d2ee523a2206206994597c13d831ec7"
let erc20ContractAddress = "0xffffffff8d2ee523a2206206994597c13d831ec7"
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

    let chainId = newWallet.chainId();
    print("chain Id:", chainId)

    newWallet.switchChain(chainId: 13371);
    let newChainId = newWallet.chainId();
    print("new chain Id:", newChainId)
}

func testNft() {
    let contract = try! Contract(address: nftContractAddress, provider: provider, wallet: wallet);
    let price = try! contract.nftCurrentPrice();
    assert(10_000_000_000_000_000 == price)

    let totalSupply = try! contract.nftTotalSupply();
    print("NFT total supply:", totalSupply)

    let txHash = try! contract.nftMint(to: "0xce381ddac7207129d81431604332a7c016492aa6", value: price);
    print("mint tx hash:", txHash)
}

func testTransferBridgeOut() {
    let contract = try! Contract(address: bridgeContractAddress, provider: provider, wallet: wallet);
    let txHash = try! contract.transferBridgeOut(to: "0x46594bb57b9CcA5a4B2c968E3A4bAFb258587308", value: 100, chainId: 0, chainType: 7);
    print("transferBridgeOut tx hash:", txHash)
}

func testErc20() {
    let contract = try! Contract(address: erc20ContractAddress, provider: provider, wallet: wallet);
    let balance = try! contract.tokenBalanceOf(address: "0xce381ddac7207129d81431604332a7c016492aa6");
    print("erc20 balance:", balance)

    let decimals = try! contract.tokenDecimals();
    print("erc20 decimals:", decimals)

    let txHash = try! contract.tokenTransfer(to:"0xE399C86c2370cCe714841e4d869e61450CD9f9de", value: 100)
    print("erc20 transfer tx hash:", txHash)
}

print("===Test New Wallet===\n")
testNewWallet()
print("===Test Decrypted Address===\n")
testDecryptedAddress()

//#NOTE Ensure that the `0xCE381DdAC7207129D81431604332a7c016492aa6` has enough ACT and USDT.
// print("===Test ERC20 USDT===\n")
// testErc20()
// print("===Test NFT===\n")
// testNft()
// print("===Test Transfer Bridge Out===\n")
// testTransferBridgeOut()