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
    implementation("com.google.code.gson:gson:2.10.1")
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

java {
    val javaVersion = JavaVersion.VERSION_17
    sourceCompatibility = javaVersion
    targetCompatibility = javaVersion
}

tasks.named<Test>("test") {
    useJUnitPlatform()
}

tasks.register<JavaExec>("runPtkMappingCheck") {
    group = "verification"
    description = "Runs the PTK↔ZAP mapping 1:1 check from the command line"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("org.zaproxy.addon.ptk.PtkMappingCheck")
}

tasks.register<JavaExec>("runPtkScannersMd") {
    group = "documentation"
    description = "Outputs PTK↔ZAP mappings in a format suitable for ZAP scanners.md"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("org.zaproxy.addon.ptk.PtkScannersMdOutput")
}

tasks.register<JavaExec>("updateZapMapping") {
    group = "documentation"
    description = "Updates zap-mapping.json from module files; preserves existing alert IDs, adds new modules/rules"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("org.zaproxy.addon.ptk.ZapMappingUpdater")
    args(
        project.file("src/main/resources/org/zaproxy/addon/ptk/zap-mapping.json").absolutePath,
    )
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
