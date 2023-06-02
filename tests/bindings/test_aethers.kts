import aethers.*;

val wallet = Wallet("123456")
val memo = wallet.recoverPhrase("123456")
val json = wallet.encryptJson()
val jsonString = "{\"crypto\":{\"cipher\":\"aes-128-ctr\",\"cipherparams\":{\"iv\":\"159f7792c62ffe92731a85d730c1613c\"},\"ciphertext\":\"3dd922c6248d07ab3fee4bd1b5d95b5e40e105eeace718355616af13f83e3e2817799379d9cd24aaf57e4c68a25e2133c62a28770856730095dbfce4d0d5d9d7841eee96776de62bfbabb610\",\"kdf\":\"scrypt\",\"kdfparams\":{\"dklen\":32,\"n\":8192,\"p\":1,\"r\":8,\"salt\":\"fc48d2e37f67b4d92c6427b3e9086ed6671dcd9dbe3dff406aec197693494506\"},\"mac\":\"2a606fb39e423c820440b7dd82ae24c477a6521d24d98f419013f1c47a916fbc\"},\"id\":\"0580948c-7ed5-4905-a045-7908971241f4\",\"version\":3}"
val wallet2 = decryptJson(json, "123456")
val wallet3 = decryptJson(jsonString, "123456")
val memo2 = wallet2.recoverPhrase("123456")
