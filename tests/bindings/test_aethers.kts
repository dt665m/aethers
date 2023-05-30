import aethers.*;

val wallet = Wallet("123456")
val memo = wallet.recoverPhrase("123456")
val json = wallet.encryptJson()
val wallet2 = decryptJson(json, "123456")
val memo2 = wallet2.recoverPhrase("123456")
