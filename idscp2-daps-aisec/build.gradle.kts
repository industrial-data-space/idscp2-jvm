version = libs.versions.idscp2.get()

val api by configurations

dependencies {
    api(project(":idscp2-api"))

    implementation(libs.kotlinx.coroutines)
    implementation(libs.bouncycastle)
    implementation(libs.bundles.jsonwebtoken)
    implementation(libs.jose4j)
    implementation(libs.bundles.ktor.richClient)
}
