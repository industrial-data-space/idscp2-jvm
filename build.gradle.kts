import com.github.benmanes.gradle.versions.updates.DependencyUpdatesTask
import org.gradle.api.tasks.testing.logging.TestExceptionFormat
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

buildscript {
    repositories {
        mavenCentral()
    }
}

plugins {
    java
    signing
    `maven-publish`
    alias(libs.plugins.kotlin)
    alias(libs.plugins.spotless)
    alias(libs.plugins.license.report)
    alias(libs.plugins.versions)
}

val descriptions: Map<String, String> = mapOf(
    "idscp2" to "IDSCP2 Protocol Implementation",
    "idscp2-app-layer" to "IDSCP2 Application Layer Implementation",
    "camel-idscp2" to "Camel IDSCP2 Component Implementation"
)

allprojects {
    group = "de.fhg.aisec.ids"

    repositories {
        mavenCentral()
        // References IAIS repository that contains the infomodel artifacts
        maven("https://maven.iais.fraunhofer.de/artifactory/eis-ids-public/")
    }

    val versionRegex = ".*(rc-?[0-9]*|beta)$".toRegex(RegexOption.IGNORE_CASE)

    tasks.withType<DependencyUpdatesTask> {
        rejectVersionIf {
            // Reject release candidates and betas and pin Apache Camel to 3.18 LTS version
            versionRegex.matches(candidate.version) || (candidate.group in setOf(
                "org.apache.camel", "org.apache.camel.springboot"
            ) && !candidate.version.startsWith("3.18"))
        }
    }
}

subprojects {
    apply(plugin = "java")
    apply(plugin = "kotlin")

    tasks.withType<Javadoc> {
        exclude("de/fhg/aisec/ids/idscp2/messages/**", "de/fhg/aisec/ids/idscp2/applayer/messages/**")
    }

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
        api(rootProject.libs.slf4j.api)
        // Kotlin JVM library
        api(rootProject.libs.kotlin.stdlib)
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

    if (project.name in descriptions.keys) {
        publishing {
            publications {
                register("idscp2Library", MavenPublication::class) {
                    from(components["java"])
                    pom {
                        name.set(project.name)
                        description.set(descriptions[project.name])
                        url.set("https://github.com/industrial-data-space/idscp2-jvm")
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
                            connection.set("scm:git:git://github.com:industrial-data-space/idscp2-jvm.git")
                            developerConnection.set("scm:git:ssh://github.com:industrial-data-space/idscp2-jvm.git")
                            url.set("https://github.com/industrial-data-space/idscp2-jvm")
                        }
                    }
                }
            }

            repositories {
                if (project.hasProperty("publishLocal")) {
                    mavenLocal()
                } else {
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
        }

        if (!project.hasProperty("publishLocal")) {
            signing {
                useGpgCmd()
                sign(publishing.publications.getByName("idscp2Library"))
            }
        }
    }

    apply(plugin = "com.github.jk1.dependency-license-report")

    apply(plugin = "com.diffplug.spotless")

    spotless {
        kotlin {
            target("src/**/*.kt")
            ktlint(libs.versions.ktlint.get())
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
