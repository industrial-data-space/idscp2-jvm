plugins {
    alias(libs.plugins.protobuf)
}

version = libs.versions.idscp2.get()

val api by configurations
val testImplementation by configurations

dependencies {
    api(project(":idscp2-api"))
    api(project(":idscp2-core"))
    api(libs.infomodel)

    implementation(libs.protobuf)
}

tasks.named("spotlessKotlin") {
    dependsOn(tasks.named("generateProto"))
    dependsOn(tasks.named("generateTestProto"))
}
