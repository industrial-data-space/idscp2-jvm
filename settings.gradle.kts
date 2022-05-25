rootProject.name = "idscp2-jvm"

pluginManagement {
    repositories {
        mavenCentral()
        gradlePluginPortal()
    }
}

include("idscp2")
include("idscp2-examples")
include("idscp2-app-layer")
include("camel-idscp2")
