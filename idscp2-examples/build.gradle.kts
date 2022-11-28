plugins {
    application
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
