@Suppress("UNCHECKED_CAST")
val libraryVersions = rootProject.extra.get("libraryVersions") as Map<String, String>

version = libraryVersions["idscp2"] ?: error("IDSCP2 version not specified")

dependencies {
    api(project(":idscp2"))
    api(project(":idscp2-app-layer"))

    api("de.fraunhofer.iais.eis.ids.infomodel", "java", libraryVersions["infomodel"])
    api("de.fraunhofer.iais.eis.ids", "infomodel-serializer", libraryVersions["infomodel"])

    api("org.apache.camel", "camel-core", libraryVersions["camel"])

    api("com.google.protobuf", "protobuf-java", libraryVersions["protobuf"])

    api("com.google.guava", "guava", libraryVersions["guava"]) {
        isTransitive = false // Avoid pulling in of checker framework and other annotation stuff
    }

    testImplementation("junit", "junit", libraryVersions["junit4"])
    testImplementation("org.apache.camel", "camel-test", libraryVersions["camel"])
    testImplementation("org.mockito", "mockito-core", libraryVersions["mockito"])
}
