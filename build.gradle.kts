import org.zaproxy.gradle.addon.AddOnStatus
import org.zaproxy.gradle.addon.misc.ConvertMarkdownToHtml

plugins {
    `java-library`
    id("org.zaproxy.add-on") version "0.13.1"
    id("com.diffplug.spotless")
    id("org.zaproxy.common")
}

repositories {
    mavenCentral()
    maven {
        url = uri("https://central.sonatype.com/repository/maven-snapshots/")
    }
}

description = "Adds the OWASP PTK extension to browsers launched from ZAP."

zapAddOn {
    addOnId.set("ptk")
    addOnName.set("OWASP PTK")
    zapVersion.set("2.17.0")
    addOnStatus.set(AddOnStatus.ALPHA)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/owasp-ptk/")
        repo.set("https://github.com/DenisPodgurskii/ZAP_PTK")
        changesFile.set(tasks.named<ConvertMarkdownToHtml>("generateManifestChanges").flatMap { it.html })

        helpSet {
            baseName.set("org.zaproxy.addon.ptk.resources.help%LC%.helpset")
            localeToken.set("%LC%")
        }

        dependencies {
            addOns {
                register("selenium")
                register("client") {
                    version.set(">=0.21.0")
                }
            }
        }
    }
}

dependencies {
    compileOnly("org.zaproxy.addon:client:0.21.0-SNAPSHOT")
}

java {
    val javaVersion = JavaVersion.VERSION_17
    sourceCompatibility = javaVersion
    targetCompatibility = javaVersion
}

spotless {
    kotlinGradle {
        ktlint()
    }
    java {
        clearSteps()
        googleJavaFormat("1.17.0").aosp()
    }
}
