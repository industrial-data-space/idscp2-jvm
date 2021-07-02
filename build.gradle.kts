import org.gradle.api.tasks.testing.logging.TestExceptionFormat
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile
import org.yaml.snakeyaml.Yaml

buildscript {
    repositories {
        mavenCentral()
    }
    dependencies {
        classpath("org.yaml:snakeyaml:1.26")
    }
}

plugins {
    java
    signing
    `maven-publish`
    id("com.google.protobuf") version "0.8.16"
    // WARNING: Versions 5.2.x onwards export java.* packages, which is not allowed in Felix OSGi Resolver!
    // See http://karaf.922171.n3.nabble.com/Manifest-import-problems-td4059042.html
    id("biz.aQute.bnd") version "5.1.2" apply false
    id("org.jetbrains.kotlin.jvm") version "1.5.20"
    id("com.diffplug.spotless") version "5.11.0"
    id("com.github.jk1.dependency-license-report") version "1.16"
}

@Suppress("UNCHECKED_CAST")
val libraryVersions: Map<String, String> =
    Yaml().loadAs(file("$rootDir/libraryVersions.yaml").inputStream(), Map::class.java) as Map<String, String>
extra.set("libraryVersions", libraryVersions)

val descriptions: Map < String, String > = mapOf(
    "idscp2" to "IDSCP2 Protocol Implementation",
    "idscp2-app-layer" to "IDSCP2 Application Layer Implementation",
    "camel-idscp2" to "Camel IDSCP2 Component Implementation"
)

allprojects {
    group = "de.fhg.aisec.ids"

    repositories {
        mavenCentral()
        jcenter()
        // References IAIS repository that contains the infomodel artifacts
        maven("https://maven.iais.fraunhofer.de/artifactory/eis-ids-public/")
    }
}

subprojects {
    apply(plugin = "biz.aQute.bnd.builder")
    apply(plugin = "java")
    apply(plugin = "kotlin")

    java {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
        withSourcesJar()
        withJavadocJar()
    }

    tasks.test {
        exclude("**/*IT.*")
    }

    val integrationTest = tasks.register<Test>("integrationTest") {
        include("**/*IT.*")
        systemProperty("project.version", "$project.version")
    }

    tasks.withType<Test> {
        testLogging {
            events("failed")
            exceptionFormat = TestExceptionFormat.FULL
        }
    }

    tasks.check {
        dependsOn(integrationTest)
    }

    // define some Bill of Materials (BOM) for all subprojects
    dependencies {
        // Logging API
        api("org.slf4j", "slf4j-api", libraryVersions["slf4j"])

        // Needed for kotlin modules, provided at runtime via kotlin-osgi-bundle in karaf-features-ids
        api("org.jetbrains.kotlin", "kotlin-stdlib-jdk8", libraryVersions["kotlin"])
    }

    tasks.withType<KotlinCompile> {
        kotlinOptions {
            jvmTarget = "11"
        }
    }

    tasks.withType<JavaCompile> {
        options.encoding = "UTF-8"
        // options.compilerArgs.add("-Xlint:unchecked")
        // options.isDeprecation = true
    }

    tasks.jar {
        manifest {
            attributes(
                "Bundle-Vendor" to "Fraunhofer AISEC",
                "-noee" to true
            )
        }
    }

    apply(plugin = "maven-publish")
    apply(plugin = "signing")

    publishing {
        publications {
            register("idscp2Library", MavenPublication::class) {
                from(components["java"])
                pom {
                    name.set(project.name)
                    description.set(descriptions[project.name])
                    url.set("https://github.com/industrial-data-space/idscp2-java")
                    licenses {
                        license {
                            name.set("The Apache License, Version 2.0")
                            url.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
                        }
                    }
                    developers {
                        developer {
                            name.set("Michael Lux")
                            email.set("michael.lux@aisec.fraunhofer.de")
                            organization.set("Fraunhofer AISEC")
                            organizationUrl.set("aisec.fraunhofer.de")
                        }
                    }
                    scm {
                        connection.set("scm:git:git://github.com:industrial-data-space/idscp2-java.git")
                        developerConnection.set("scm:git:ssh://github.com:industrial-data-space/idscp2-java.git")
                        url.set("https://github.com/industrial-data-space/idscp2-java")
                    }
                }
            }
        }

        repositories {
            // mavenLocal()
            maven {
                url = uri(
                    if (version.toString().endsWith("SNAPSHOT")) {
                        "https://oss.sonatype.org/content/repositories/snapshots"
                    } else {
                        "https://oss.sonatype.org/service/local/staging/deploy/maven2"
                    }
                )

                credentials {
                    username = project.findProperty("deployUsername") as? String
                    password = project.findProperty("deployPassword") as? String
                }
            }
        }
    }

    signing {
        useGpgCmd()
        sign(publishing.publications.getByName("idscp2Library"))
    }

    apply(plugin = "com.github.jk1.dependency-license-report")

    apply(plugin = "com.diffplug.spotless")

    spotless {
        kotlin {
            target("**/*.kt")
            ktlint(libraryVersions["ktlint"])
            licenseHeader(
                """/*-
 * ========================LICENSE_START=================================
 * ${project.name}
 * %%
 * Copyright (C) ${"$"}YEAR Fraunhofer AISEC
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * =========================LICENSE_END==================================
 */"""
            ).yearSeparator(" - ")
        }
    }
}
