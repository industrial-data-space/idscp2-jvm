plugins {
    alias(libs.plugins.protobuf)
}

version = libs.versions.idscp2.get()

dependencies {
    implementation(libs.bouncycastle)
    implementation(libs.protobuf)
}

tasks.named("spotlessKotlin") {
    dependsOn(tasks.named("generateProto"))
    dependsOn(tasks.named("generateTestProto"))
}
