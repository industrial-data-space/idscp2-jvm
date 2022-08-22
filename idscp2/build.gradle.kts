import com.google.protobuf.gradle.protobuf
import org.gradle.plugins.ide.idea.model.IdeaModel

version = libs.versions.idscp2.get()

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
    implementation(libs.kotlinx.coroutines)

    implementation(libs.bouncycastle)

    implementation(libs.protobuf)

    implementation(libs.bundles.jsonwebtoken)
    implementation(libs.jose4j)
    implementation(libs.bundles.ktor.richClient)

    testImplementation(libs.awaitility)
    testImplementation(libs.junit)
    testImplementation(libs.mockito)
}

tasks.named("spotlessKotlin") {
    dependsOn(tasks.named("generateProto"))
    dependsOn(tasks.named("generateTestProto"))
}
