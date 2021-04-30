import com.google.protobuf.gradle.protobuf
import com.google.protobuf.gradle.protoc
import org.gradle.nativeplatform.platform.internal.ArchitectureInternal
import org.gradle.nativeplatform.platform.internal.DefaultNativePlatform
import org.gradle.plugins.ide.idea.model.IdeaModel


@Suppress("UNCHECKED_CAST")
val libraryVersions = rootProject.extra.get("libraryVersions") as Map<String, String>

version = libraryVersions["idscp2"] ?: error("IDSCP2 version not specified")

apply(plugin = "java")
apply(plugin = "com.google.protobuf")
apply(plugin = "idea")

val generatedProtoBaseDir = "$projectDir/generated"
val os: OperatingSystem = DefaultNativePlatform.getCurrentOperatingSystem()
val arch: Architecture = DefaultNativePlatform.getCurrentArchitecture()

protobuf {
    generatedFilesBaseDir = generatedProtoBaseDir

    if(os.isMacOsX && arch.name == "aarch64") { // needs to be changed to "arm-v8" for gradle 7.0
        // protoc needs to be available in the system, e.g. via homebrew
    } else {
        protoc {
            // Download from repositories
            artifact = "com.google.protobuf:protoc:3.9.2"
        }
    }
}


tasks.named("clean") {
    doLast {
        delete(generatedProtoBaseDir)
    }
}

configure<IdeaModel> {
    module {
        // mark as generated sources for IDEA
        generatedSourceDirs.add(File("$generatedProtoBaseDir/main/java"))
    }
}

val api by configurations
val testImplementation by configurations

dependencies {
    api("org.jetbrains.kotlinx", "kotlinx-coroutines-core-jvm", libraryVersions["kotlinxCoroutines"])

    api("org.bouncycastle", "bcprov-jdk15on", libraryVersions["bouncycastle"])

    api("com.google.protobuf", "protobuf-java", libraryVersions["protobuf"])

    api("io.jsonwebtoken", "jjwt-impl", libraryVersions["jsonwebtoken"])
    api("io.jsonwebtoken", "jjwt-jackson", libraryVersions["jsonwebtoken"])
    api("io.jsonwebtoken", "jjwt-api", libraryVersions["jsonwebtoken"])
    api("org.json", "json", libraryVersions["orgJson"])
    api("org.bitbucket.b_c", "jose4j", libraryVersions["jose4j"])
    api("com.squareup.okhttp3", "okhttp", libraryVersions["okhttp"])

    testImplementation("org.awaitility", "awaitility-kotlin", libraryVersions["awaitility"])
    testImplementation("junit", "junit", libraryVersions["junit4"])
    testImplementation("org.mockito", "mockito-core", libraryVersions["mockito"])
}
