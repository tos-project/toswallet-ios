TosWallet for iOS
----------------------------------

[Download here](http://toswallet.tosblock.com/download/)

## Toscoin done right

The simplest and most secure Toscoin wallet on any platform

### The first standalone iOS Toscoin wallet:

Unlike other iOS bitcoin wallets, **TosWallet** is a real standalone Toscoin client. There is no server to get hacked or go down, so you can always access your money. Using [SPV](https://en.bitcoin.it/wiki/Thin_Client_Security#Header-Only_Clients) mode, **TosWallet** connects directly to the Toscoin network with the fast performance you need on a mobile device.

### The next step in wallet security:

**TosWallet** is designed to protect you from malware, browser security holes, *even physical theft*. With AES hardware encryption, app sandboxing, keychain and code signatures, TosWallet represents a significant security advance over web and desktop wallets, and other mobile platforms.

### Beautiful simplicity:

Simplicity is **TosWallet**'s core design principle. A simple backup phrase is all you need to restore your wallet on another device if yours is ever lost or broken.  Because **TosWallet** is [deterministic](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki), your balance and transaction history can be recovered from just your backup phrase.

### Features:
- Securely store your TOS coin addresses and their private keys.
- Directly connect to the TOS coin Network using SPV[(Simplified payment verification)](https://github.com/bitcoin/bips/blob/master/bip-0037.mediawiki) mode.
- Import [password protected](https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki) paper wallets
- Create multiple wallets with multiple TOS coin addresses for each wallet.
- Create wallets for TOS coin.
- ["Payment protocol"](https://github.com/bitcoin/bips/blob/master/bip-0070.mediawiki) payee identity certification
- Send payments directly from the app.
- Receive notifications when new transactions occur in your wallet.
- Check balances and transactions in each wallet with different TOS coin address.
- Verify balances and transactions from multiple data sources.
- Check the price of TOS coin, in multiple currencies, from all TOS coin exchanges.
- TOS Wallet is FREE. for now.

### URL scheme:

**TosWallet** supports the [x-callback-url](http://x-callback-url.com) specification with the following URLs:

```
loaf://x-callback-url/address?x-success=myscheme://myaction
```

This will callback with the current wallet receive address: `myscheme://myaction?address=1XXXX`

The following will ask the user to authorize copying a list of their wallet addresses to the clipboard before calling back:

```
loaf://x-callback-url/addresslist?x-success=myscheme://myaction
```

### WARNING:

***Installation on jailbroken devices is strongly discouraged.***

Any jailbreak app can grant itself access to every other app's keychain data and rob you by self-signing as described [here](http://www.saurik.com/id/8) and including `<key>application-identifier</key><string>*</string>` in its .entitlements file.

---

**TosWallet** is open source and available under the terms of the MIT license.

Source code is available at https://github.com/toscoin-project/toswallet-ios/
