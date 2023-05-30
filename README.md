#

## Android Targets 
- aarch64-linux-android(arm64-v8a)
- armv7-linux-androideabi(armeabi-v7a) 

## iOS Targets
- aarch64-apple-ios
- aarch64-apple-ios-sim

## Uniffi Swift Steps
- Build rust for all ios platforms
- Build uniffi bindings
- Include uniffi generated header file in a bridge header 
(Build Settings->General->ObjectiveC bridging Header if it doesn't exists)
- In Xcode, include the generated uniffi swift file by adding it
- Link up the '.a' files either through .pbxproj file or in xcode general settings

## Uniffi Kotlin Steps
- ?

## XCFramework 
- https://github.com/imWildCat/uniffi-rs-fullstack-examples/tree/main/hello

### Trust Wallet Integration
Trust Wallet Provider's setup is broken down into the Javascript portion and the Native to Javascript
binding.  The Provider is in the following way:

TrustWalletProvider.swift:
- The native code holds config values such as chain, network and provider url as strings
- The JS shim is compiled into a minimized js bundle and loaded as injectable by the native code
- The instantiating code for the JS shim is loaded as injectable by the native code with the native config

WKWebView+Extension.swift
- This extends the WebView with functions that call into javascript by creating some TypeWrapper
Facade which basically just calls into the WKWebView.evaluateJavascript.  This nicely wraps the
injected javascript invocation in native 

DAppWebviewController.swift:
- This file handles the script injection and js message callback registration of the WebView (line 74)
- On message from JS, the handler fans out the call to the correct function which then responds back
    - Call TrustWalletCore(lower level bindings)
    - Call WKWebView+Extension to set state in the JS Shim (sometimes)
    - Call WkWebView+Extension to return RPC response to the JS Shim
    - An int64 ID is used to keep track of the request+response
