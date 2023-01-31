ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)

SGX_SIGNER_KEY ?= ~/.config/gramine/enclave-key.pem

# This Makefile is targeted towards the client. The server is assumed to run outside SGX.

.PHONY: client
client:
	./gradlew nativeBuild -PnativeImageName=idscp2-native-client -PmainNativeClass=de.fhg.aisec.ids.idscp2.example.RunTLSClient
	cp idscp2-examples/build/native/nativeCompile/idscp2-native-client .

.PHONY: gramine
gramine: idscp2-native.manifest idscp2-native.manifest.sgx idscp2-native.sig idscp2-native.token

.PHONY: all
all: client gramine

idscp2-native.manifest: idscp2-native.manifest.template
	gramine-manifest \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dentrypoint=idscp2-native-client \
		$< > $@

idscp2-native.manifest.sgx: idscp2-native.manifest
	@test -s $(SGX_SIGNER_KEY) || \
	    { echo "SGX signer private key was not found, please specify SGX_SIGNER_KEY!"; exit 1; }
	gramine-sgx-sign \
		--key $(SGX_SIGNER_KEY) \
		--manifest $< \
		--output $@

idscp2-native.sig: idscp2-native.manifest.sgx

idscp2-native.token: idscp2-native.sig
	gramine-sgx-get-token --output $@ --sig $<

clean-client:
	$(RM) idscp2-native-client

clean-gramine:
	$(RM) *.token *.sig *.manifest.sgx *.manifest

.PHONY: clean
clean: clean-client clean-gramine
