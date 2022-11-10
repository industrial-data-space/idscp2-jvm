plugins {
    alias(libs.plugins.protobuf)
}

version = libs.versions.idscp2.get()

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
