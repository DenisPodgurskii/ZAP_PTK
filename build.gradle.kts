import org.gradle.api.tasks.Exec
import org.zaproxy.gradle.addon.AddOnStatus
import org.zaproxy.gradle.addon.misc.ConvertMarkdownToHtml
import java.util.zip.ZipFile

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

val diagnosticBuild =
    providers.gradleProperty("ptkDiagnostic").map { it.equals("true", ignoreCase = true) }.orElse(false).get()

if (diagnosticBuild) {
    version = "${project.version}-diagnostic"
}

val automationVersion = "0.60.0"
val automationZapFile =
    layout.buildDirectory.file("zap-addons/automation-beta-$automationVersion.zap")
val automationZapUrl =
    "https://github.com/zaproxy/zap-extensions/releases/download/" +
        "automation-v$automationVersion/automation-beta-$automationVersion.zap"

// Diagnostic-only classpath workaround until the Automation add-on is available as a Maven dependency.
val downloadAutomationZap =
    if (diagnosticBuild) {
        tasks.register("downloadAutomationZap") {
            inputs.property("automationVersion", automationVersion)
            inputs.property("automationZapUrl", automationZapUrl)
            outputs.file(automationZapFile)
            outputs.upToDateWhen { automationZapFile.get().asFile.isFile }
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
    } else {
        null
    }

description = "Adds the OWASP PTK extension to browsers launched from ZAP."

zapAddOn {
    addOnId.set("ptk")
    addOnName.set(if (diagnosticBuild) "OWASP PTK Diagnostic" else "OWASP PTK")
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
                if (diagnosticBuild) {
                    register("automation")
                }
                register("selenium")
                register("client") {
                    version.set(">=0.21.0")
                }
            }
        }
    }
}

sourceSets {
    named("main") {
        if (diagnosticBuild) {
            java.srcDir("src/diagnostic/java")
            resources.srcDir("src/diagnostic/resources")
        }
    }
    named("test") {
        if (diagnosticBuild) {
            java.srcDir("src/diagnosticTest/java")
            resources.srcDir("src/diagnosticTest/resources")
        }
    }
}

dependencies {
    compileOnly("com.fasterxml.jackson.core:jackson-annotations:2.20")
    compileOnly("org.zaproxy.addon:client:0.22.0-SNAPSHOT")
    compileOnly("org.zaproxy.addon:selenium:15.43.0")
    compileOnly("org.projectlombok:lombok:1.18.34")
    annotationProcessor("org.projectlombok:lombok:1.18.34")
    implementation("com.google.code.gson:gson:2.10.1")
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
    testCompileOnly("com.fasterxml.jackson.core:jackson-annotations:2.20")
    testCompileOnly("org.zaproxy.addon:client:0.22.0-SNAPSHOT")
    testCompileOnly("org.zaproxy.addon:selenium:15.43.0")
    testRuntimeOnly("com.fasterxml.jackson.core:jackson-annotations:2.20")
    testRuntimeOnly("org.zaproxy.addon:client:0.22.0-SNAPSHOT")
    testRuntimeOnly("org.zaproxy.addon:selenium:15.43.0")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    if (diagnosticBuild) {
        compileOnly(files(automationZapFile))
        testCompileOnly(files(automationZapFile))
        testRuntimeOnly(files(automationZapFile))
    }
}

java {
    val javaVersion = JavaVersion.VERSION_17
    sourceCompatibility = javaVersion
    targetCompatibility = javaVersion
}

tasks.withType<JavaCompile>().configureEach {
    downloadAutomationZap?.let { dependsOn(it) }
    val lintFlags = mutableListOf("-processing")
    if (JavaVersion.current().getMajorVersion() >= "21") {
        lintFlags.add("-this-escape")
    }
    options.compilerArgs = options.compilerArgs + "-Xlint:${lintFlags.joinToString(",")}"
}

tasks.named<Test>("test") {
    useJUnitPlatform()
}

if (!diagnosticBuild) {
    fun gradleWrapperCommand(): List<String> =
        if (System.getProperty("os.name").lowercase().contains("windows")) {
            listOf("cmd", "/c", "gradlew.bat")
        } else {
            listOf("./gradlew")
        }

    tasks.register<Exec>("jarZapAddOnDiagnostic") {
        group = "build"
        description = "Builds an internal diagnostic .zap containing ptkBrowserCoverage."
        workingDir = projectDir
        commandLine(gradleWrapperCommand() + listOf("-PptkDiagnostic=true", "jarZapAddOn"))
    }

    tasks.register<Exec>("testDiagnostic") {
        group = "verification"
        description = "Runs tests with diagnostic-only source sets enabled."
        workingDir = projectDir
        commandLine(gradleWrapperCommand() + listOf("-PptkDiagnostic=true", "test"))
    }
}

val verifyProductionArtifactClean =
    tasks.register("verifyProductionArtifactClean") {
        group = "verification"
        description = "Verifies the production .zap does not contain diagnostic-only classes."
        onlyIf { !diagnosticBuild }
        doLast {
            val zapDir = layout.buildDirectory.dir("zapAddOn/bin").get().asFile
            val zapFiles =
                zapDir.listFiles { file -> file.isFile && file.name.endsWith(".zap") }
                    ?.toList()
                    ?: emptyList()
            if (zapFiles.isEmpty()) {
                throw GradleException("No production .zap found under ${zapDir.absolutePath}")
            }
            val forbiddenEntries =
                listOf(
                    "org/zaproxy/addon/ptk/PtkBrowserCoverageJob.class",
                    "org/zaproxy/addon/ptk/PtkBrowserCoverageDiagnostic.class",
                    "org/zaproxy/addon/ptk/PtkBrowserCoverageTiming.class",
                    "META-INF/services/org.zaproxy.addon.ptk.PtkDiagnosticExtension",
                )
            for (zapFile in zapFiles) {
                ZipFile(zapFile).use { zip ->
                    val names = zip.entries().asSequence().map { it.name }.toSet()
                    val present = forbiddenEntries.filter(names::contains)
                    if (present.isNotEmpty()) {
                        throw GradleException(
                            "Production artifact ${zapFile.name} contains diagnostic entries: $present",
                        )
                    }
                }
            }
        }
    }

if (!diagnosticBuild) {
    verifyProductionArtifactClean.configure {
        dependsOn(tasks.named("jarZapAddOn"))
    }
}

tasks.named("check") {
    if (!diagnosticBuild) {
        dependsOn(verifyProductionArtifactClean)
    }
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
