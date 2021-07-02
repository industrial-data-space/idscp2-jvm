plugins {
    application
}

@Suppress("UNCHECKED_CAST")
val libraryVersions = rootProject.extra.get("libraryVersions") as Map<String, String>

version = libraryVersions["idscp2"] ?: error("IDSCP2 version not specified")

apply(plugin = "java")

val api by configurations

dependencies {
    api(project(":idscp2"))

    api("org.slf4j", "slf4j-simple", libraryVersions["slf4j"])
}

application {
    mainClass.set(
        findProperty("mainClass")?.toString()
            ?: "de.fhg.aisec.ids.idscp2.example.RunTLSServer"
    )
}
