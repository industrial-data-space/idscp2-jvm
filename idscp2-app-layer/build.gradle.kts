import com.google.protobuf.gradle.protobuf
import org.gradle.plugins.ide.idea.model.IdeaModel

@Suppress("UNCHECKED_CAST")
val libraryVersions = rootProject.extra.get("libraryVersions") as Map<String, String>

version = libraryVersions["idscp2"] ?: error("IDSCP2 version not specified")

apply(plugin = "java")
apply(plugin = "com.google.protobuf")
apply(plugin = "idea")

val generatedProtoBaseDir = "$projectDir/generated"

protobuf {
    generatedFilesBaseDir = generatedProtoBaseDir
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

tasks.named("spotlessKotlin") {
    dependsOn(tasks.named("generateProto"))
    dependsOn(tasks.named("generateTestProto"))
}
