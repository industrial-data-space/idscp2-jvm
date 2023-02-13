# IDSCP2 (JVM)

[![build](https://github.com/industrial-data-space/idscp2-jvm/actions/workflows/build.yml/badge.svg)](https://github.com/industrial-data-space/idscp2-jvm/actions/workflows/build.yml)

This is the official Kotlin-based implementation of the IDS Communication Protocol (IDSCP2) for use in JVM environments.

## Build

```bash
./gradlew build
```

## Usage

Maven artifacts are pushed to maven central and can be found here: https://search.maven.org/search?q=idscp2.

More information about the usage can be found in the [IDSCP2 Documentation](https://github.com/industrial-data-space/idscp2-jvm/wiki).

## Intel SGX Support

IDSCP2 can make use of Intel SGX to attest Client nodes upon Server requests using the _Intel Attestation Services (IAS)_. Before the handshake is built, the Server sends the Client a nonce, which must be included in an SGX quote. When the Server receives the quote, it sends it to IAS and verifies whether the quote's payload corresponds to the initial nonce value. If both checks pass, the Server accepts the Client's handshake.

### System Requirements

- [Ubuntu 20.04](https://releases.ubuntu.com/focal/) or above
- [Intel SGX SDK](https://github.com/intel/linux-sgx)
- [GraalVM for Java 17](https://github.com/graalvm/graalvm-ce-builds/releases)
- [Gramine SGX](https://github.com/gramineproject/gramine)

### Installation Guide

In this section we detail the setup process for SGX support of a system running **Ubuntu 22.04**.

#### Intel SGX SDK

1. We start by setting up the SGX SDK. The current stable version is **2.18.1**. We first install all necessary dependencies:
    ```bash
    sudo apt-get install build-essential ocaml ocamlbuild automake autoconf libtool wget python-is-python3 \
        libssl-dev git cmake perl libssl-dev libcurl4-openssl-dev protobuf-compiler \
        libprotobuf-dev debhelper cmake reprepro unzip pkgconf libboost-dev libboost-system-dev libboost-thread-dev \
        protobuf-c-compiler libprotobuf-c-dev lsb-release libsystemd0 python2
    ```

2. We can now clone the SDK repository and start building it:
    ```bash
    git clone https://github.com/intel/linux-sgx.git
    cd linux-sgx && make preparation
    sudo cp external/toolset/ubuntu20.04/* /usr/local/bin
    make sdk_install_pkg
    ```

3. To be able to use Gramine SGX, we will also need the _Intel Platform SoftWare (PSW)_:
    ```bash
    make psw
    make deb_psw_pkg
    ```

4. Installing the SDK is first done through the generated installer. The PSW is composed of multiple `.deb` packages which will be installed individually afterward.
    ```bash
    cd linux/installer/bin
    sudo ./sgx_linux_x64_sdk_2.18.101.1.bin --prefix /opt/intel
    source /opt/intel/sgxsdk/environment
    cd ../../../ && cd linux/installer/deb
    ```

    Note that the PSW packages cannot be installed in a random order, since many are the dependencies of others. Therefore, we choose the following order of installation:
    - `libsgx-headers`
    - `libsgx-launch`
    - `libsgx-enclave-common`
    - `libsgx-epid`
    - `libsgx-quote-ex`
    - `libsgx-uae-service`
    - `libsgx-urts`
    - `sgx-aesm-service/libsgx-ra-network`
    - `sgx-aesm-service/libsgx-ra-uefi`
    - `sgx-asem-service/libsgx-dcap-default-qpl`
    - `sgx-aesm-service/libsgx-dcap-quote-verify`
    - `sgx-aesm-service/libsgx-ae-*`
    - `sgx-aesm-service/libsgx-pce-logic`
    - `sgx-aesm-service/libsgx-qe3-logic`
    - `sgx-asem-service/libsgx-dcap-ql`
    - `sgx-aesm-service/sgx-aesm-service`
    - `sgx-aesm-service/libsgx-aesm-*`

    The installation of a package can be performed with the following command:
    ```bash
    sudo apt install ./<package-name>.deb
    ```

#### GraalVM for Java 17

1. The latest version of GraalVM upon writing this document is **22.3.0**. We download the GraalVM archive using the following download [link](https://github.com/graalvm/graalvm-ce-builds/releases/download/vm-22.3.0/graalvm-ce-java17-linux-amd64-22.3.0.tar.gz). We then extract the contents using:
    ```bash
    tar -xzf graalvm-ce-java17-linux-amd64-22.3.0.tar.gz
    ```

2. To be able to use Java, we need to adapt two global variables: `PATH` and `JAVA_HOME`. To accommodate this, we choose to include the following lines at the end of the `.bashrc` file:
    ```bash
    export PATH=/home/ubuntu/graalvm-ce-java17-22.3.0/bin:$PATH
    export JAVA_HOME=/home/ubuntu/graalvm-ce-java17-22.3.0
    ```
    We now need to recompile it for the changes to take effect:
    ```bash
    source .bashrc
    ```

3. To compile the Kotlin codebase, we need Native Image:
    ```bash
    gu install native-image
    ```

#### Gramine SGX

1. We start by installing all dependencies:
    ```bash
    sudo apt-get install -y build-essential \
        autoconf bison gawk nasm ninja-build pkg-config python3 python3-click meson \
        python3-jinja2 python3-pip python3-pyelftools wget libunwind8 musl-tools \
        python3-pytest libgmp-dev libmpfr-dev libmpc-dev libisl-dev python3-protobuf
    ```

2. We can now clone Gramine. The version used for testing is **1.3.1**:
    ```bash
    git clone https://github.com/gramineproject/gramine.git
    cd gramine && git checkout v1.3.1
    ```

3. We finally move on to the building and installation process:
    ```bash
    meson setup build/ --buildtype=release -Ddirect=enabled -Dsgx=enabled --prefix=/usr
    ninja -C build/
    sudo ninja -C build/ install
    ```

    > Note that we use a custom installation path for installing Gramine. This is due to a bug in version **1.3.1** on Ubuntu 22.04 which prevents Python from finding `graminelibos`. If this does not solve the problem, try also exporting the global variable ``PYTHONPATH`` as follows:
    > ```bash
    > export PYTHONPATH=$PYTHONPATH:/usr/local/graminelibos
    > ```

### Execution Instructions

Before building and running either of the two parties, we must provide **3** pieces of information to the underlying codebase:
1. In [idscp2-native.manifest.template](idscp2-native.manifest.template), insert the **SPID** of the _Intel SGX Attestation Service (Linkable)_ subscription,
2. In [GramineRaVerifier.kt](idscp2-core/src/main/kotlin/de/fhg/aisec/ids/idscp2/defaultdrivers/remoteattestation/gramine/GramineRaVerifier.kt), insert the corresponding **Primary Key**,
3. In the directory [idscp2-examples/src/main/resources/ssl](idscp2-examples/src/main/resources/ssl), insert the **Key Store** file named `localhost.p12`.

Having configured our environment, we can now execute IDSCP2 using Intel SGX. From the root directory of this project, we first run the Server:
```bash
./gradlew run
```

From a separate command prompt, we build the Client using the given Makefile:
```bash
make all
```

After the build process is done, we run the Client:
```bash
sudo gramine-sgx idscp2-native
```

If all went well, both parties should display a successful handshake.
