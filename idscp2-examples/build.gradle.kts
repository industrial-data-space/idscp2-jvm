plugins {
    application
    id("org.graalvm.buildtools.native") version "0.9.11"
}

version = libs.versions.idscp2.get()

apply(plugin = "java")

val api by configurations

dependencies {
    api(project(":idscp2-api"))

    implementation(project(":idscp2-core"))
    implementation(project(":idscp2-daps-aisec"))
    implementation(libs.slf4j.impl)
}

application {
    mainClass.set(
        findProperty("mainClass")?.toString()
            ?: "de.fhg.aisec.ids.idscp2.example.RunTLSServer"
    )
}

graalvmNative {
    binaries {
        named("main") {
            imageName.set(
                findProperty("nativeImageName")?.toString()
                    ?: "idscp2-native"
            )
            mainClass.set(
                findProperty("mainNativeClass")?.toString()
                    ?: "de.fhg.aisec.ids.idscp2.example.RunTLSServer"
            )
            runtimeArgs.add("--report-unsupported-elements-at-runtime")
            buildArgs.add("-H:ReflectionConfigurationFiles=../../../src/main/resources/reflect-config.json")
            buildArgs.add("-H:ResourceConfigurationFiles=../../../src/main/resources/resource-config.json")
        }
    }
}
