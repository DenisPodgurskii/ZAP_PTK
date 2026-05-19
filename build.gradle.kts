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

val automationVersion = "0.60.0"
val automationZapFile =
    layout.buildDirectory.file("zap-addons/automation-beta-$automationVersion.zap")
val automationZapUrl =
    "https://github.com/zaproxy/zap-extensions/releases/download/" +
        "automation-v$automationVersion/automation-beta-$automationVersion.zap"

val downloadAutomationZap by tasks.registering {
    outputs.file(automationZapFile)
    doLast {
        val outputFile = automationZapFile.get().asFile
        outputFile.parentFile.mkdirs()
        ant.withGroovyBuilder {
            "get"(
                "src" to automationZapUrl,
                "dest" to outputFile,
                "usetimestamp" to true,
            )
        }
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
                register("automation")
                register("selenium")
                register("client") {
                    version.set(">=0.21.0")
                }
            }
        }
    }
}

dependencies {
    compileOnly(files(automationZapFile))
    compileOnly("com.fasterxml.jackson.core:jackson-annotations:2.20")
    compileOnly("org.zaproxy.addon:client:0.22.0-SNAPSHOT")
    compileOnly("org.zaproxy.addon:selenium:15.43.0")
    compileOnly("org.projectlombok:lombok:1.18.34")
    annotationProcessor("org.projectlombok:lombok:1.18.34")
    implementation("com.google.code.gson:gson:2.10.1")
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

java {
    val javaVersion = JavaVersion.VERSION_17
    sourceCompatibility = javaVersion
    targetCompatibility = javaVersion
}

tasks.withType<JavaCompile>().configureEach {
    dependsOn(downloadAutomationZap)
    val lintFlags = mutableListOf("-processing")
    if (JavaVersion.current().getMajorVersion() >= "21") {
        lintFlags.add("-this-escape")
    }
    options.compilerArgs = options.compilerArgs + "-Xlint:${lintFlags.joinToString(",")}"
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
