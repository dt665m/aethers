set dotenv-load

# Path and Variables
ORG := "dt665m"
PROJECT := "aethers"
REPO := "https://github.com" / ORG / PROJECT
ROOT_DIR := justfile_directory()
OUTPUT_DIR := ROOT_DIR / "target"
SEM_VER := `awk -F' = ' '$1=="version"{print $2;exit;}' ./Cargo.toml`

default:
    @just --choose

###########################################################
### Build 

jna:
    curl https://repo1.maven.org/maven2/net/java/dev/jna/jna/5.13.0/jna-5.13.0.jar --output target/jna-5.13.0.jar --silent

deps:
    rustup target add \
        aarch64-apple-ios \
        aarch64-apple-ios-sim \
        aarch64-linux-android \
        armv7-linux-androideabi
    cargo install cargo-ndk

###########################################################
### Build 

android-builder:
    docker build --platform linux/x86_64 -f Dockerfile.android -t gcr.io/aetheras-io/android-builder:latest .

build-ios:
    rm -rf target/lib
    mkdir -p target/lib/aarch64-apple-ios
    mkdir -p target/lib/aarch64-apple-ios-sim

    cargo rustc -p aethers --lib --crate-type staticlib --release --target aarch64-apple-ios
    cargo rustc -p aethers --lib --crate-type staticlib --release --target aarch64-apple-ios-sim

    cp target/aarch64-apple-ios/release/libaethers.a target/lib/aarch64-apple-ios
    cp target/aarch64-apple-ios-sim/release/libaethers.a target/lib/aarch64-apple-ios-sim

build-android:
    docker run --platform linux/x86_64 --rm -ti -v ${PWD}:/home/dev/project gcr.io/aetheras-io/android-builder:latest \
    bash -c "cd project && cargo ndk -t armeabi-v7a -t arm64-v8a -o ./target/jniLibs build --config net.git-fetch-with-cli=true --release"

build-bindings: kotlin-bindings swift-bindings

kotlin-bindings:
    rm -rf target/bindings/kotlin
    mkdir -p target/bindings/kotlin
    cargo run --bin uniffi-bindgen generate src/aethers.udl --language kotlin -o target/bindings/kotlin

swift-bindings:
    rm -rf target/bindings/swift
    mkdir -p target/bindings/swift
    cargo run --bin uniffi-bindgen generate src/aethers.udl --language swift -o target/bindings/swift

# #NOTE this is not working.  Need to learn how to bundle a multi-platform XCFoundation swift module
swift-module:
    swiftc -module-name aethers \
    -emit-library -o aethers.dylib \
    -emit-module -emit-module-path ./target \
    -parse-as-library \
    -L target/aarch64-apple-ios/release/ \
    -laethers \
    -Xcc -fmodule-map-file=target/bindings/swift/aethersFFI.modulemap \
    target/bindings/swift/aethers.swift

###########################################################
### Test

test-swift:
    cargo test --test test_generated_bindings

export CLASSPATH := OUTPUT_DIR / "jna-5.13.0.jar"
test-kotlin: jna
    cargo test --test test_generated_bindings_kt
    
test-kotlin-docker:
    docker run --platform linux/x86_64 --rm -ti -v ${PWD}:/home/dev/project gcr.io/aetheras-io/android-builder:latest \
    bash -c "cd project && cargo test --test test_generated_bindings_kt"
    

###########################################################
### Docker

docker-builder:
	docker build \
		-t gcr.io/aetheras-shared/rustffi:1.68.0 \
		-f Dockerfile.build .
