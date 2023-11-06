version = "4.1.3"

plugins {
    kotlin("jvm")
}

repositories {
    mavenCentral()
}

val imJars = fileTree("libs") {
    include("*.jar")
}

dependencies {
    api(imJars)
    // Jackson Databind (includes Core and Annotations)
    implementation(libs.jackson.databind)
    // No CVEs with jena-core > 4.1.0
    implementation("org.apache.jena:jena-arq:4.1.0")
    implementation("org.apache.jena:jena-core:4.10.0")
}

tasks.named<Jar>("jar") {
    imJars.files.map {
        from(zipTree(it)) {
            include("**/*.class")
        }
    }
}
