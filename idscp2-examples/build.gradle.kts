plugins {
    application
    id("org.graalvm.buildtools.native") version "0.9.11"
}

@Suppress("UNCHECKED_CAST")
val libraryVersions = rootProject.extra.get("libraryVersions") as Map<String, String>

version = libraryVersions["idscp2"] ?: error("IDSCP2 version not specified")

apply(plugin = "java")

val api by configurations

dependencies {
    api(project(":idscp2"))

    implementation("org.slf4j", "slf4j-simple", libraryVersions["slf4j"])
}

application {
    mainClass.set(
        findProperty("mainClass")?.toString()
            ?: "de.fhg.aisec.ids.idscp2.example.RunTLSClient"
    )
}

graalvmNative {
    binaries {
        named("main") {
            imageName.set("idscp2-native")
            mainClass.set(
                findProperty("mainNativeClass")?.toString()
                    ?: "de.fhg.aisec.ids.idscp2.example.RunTLSClient"
            )
            runtimeArgs.add("--report-unsupported-elements-at-runtime")
            buildArgs.add("-H:ReflectionConfigurationFiles=../../../src/main/resources/reflect-config.json")
            buildArgs.add("-H:ResourceConfigurationFiles=../../../src/main/resources/resource-config.json")
//            buildArgs.add("-Ob") // Enables quick build, DISABLE THIS FOR PRODUCTION!
//            verbose.set(true)
//            debug.set(true)
//            agent.set(true)
        }
    }
}
