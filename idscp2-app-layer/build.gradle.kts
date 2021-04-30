import com.google.protobuf.gradle.protobuf
import com.google.protobuf.gradle.protoc
import org.gradle.plugins.ide.idea.model.IdeaModel

@Suppress("UNCHECKED_CAST")
val libraryVersions = rootProject.extra.get("libraryVersions") as Map<String, String>

version = libraryVersions["idscp2"] ?: error("IDSCP2 version not specified")

apply(plugin = "java")
apply(plugin = "com.google.protobuf")
apply(plugin = "idea")

val generatedProtoBaseDir = "$projectDir/generated"
val os: OperatingSystem = org.gradle.nativeplatform.platform.internal.DefaultNativePlatform.getCurrentOperatingSystem()
val arch: Architecture = org.gradle.nativeplatform.platform.internal.DefaultNativePlatform.getCurrentArchitecture()

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
    api(project(":idscp2"))

    api("com.google.protobuf", "protobuf-java", libraryVersions["protobuf"])

    // Supplied by ids-infomodel-manager
    api("de.fraunhofer.iais.eis.ids.infomodel", "java", libraryVersions["infomodel"])
    api("de.fraunhofer.iais.eis.ids", "infomodel-serializer", libraryVersions["infomodel"])
}
