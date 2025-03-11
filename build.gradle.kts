plugins {
    id("java")
    id("org.jetbrains.intellij") version "1.17.2"
}

group = "com.redaction"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
    maven { url = uri("https://packages.jetbrains.team/maven/p/ij/intellij-dependencies") }
}

// Configure Gradle IntelliJ Plugin
intellij {
    version.set("2023.1.4")
    type.set("IC") // IntelliJ IDEA Community Edition
    plugins.set(listOf("com.intellij.java"))
}

dependencies {
    // JUnit 4
    testImplementation("junit:junit:4.13.2")
    
    // Mockito
    testImplementation("org.mockito:mockito-core:3.12.4")
    
    // Gson
    implementation("com.google.code.gson:gson:2.10.1")
}

tasks {
    // Set the JVM compatibility versions
    withType<JavaCompile> {
        sourceCompatibility = "11"
        targetCompatibility = "11"
    }

    patchPluginXml {
        sinceBuild.set("233")
        untilBuild.set("241.*")
        changeNotes.set("""
            <ul>
                <li>1.0.0
                    <ul>
                        <li>支持自动检测和脱敏敏感信息</li>
                        <li>支持多种中间件配置脱敏</li>
                        <li>支持批量处理整个项目</li>
                        <li>智能识别配置占位符</li>
                    </ul>
                </li>
            </ul>
        """.trimIndent())
    }

    signPlugin {
        certificateChain.set(System.getenv("CERTIFICATE_CHAIN"))
        privateKey.set(System.getenv("PRIVATE_KEY"))
        password.set(System.getenv("PRIVATE_KEY_PASSWORD"))
    }

    publishPlugin {
        token.set(System.getenv("PUBLISH_TOKEN"))
        channels.set(listOf("default"))
    }

    buildSearchableOptions {
        enabled = false
    }

    test {
        useJUnit()
    }
} 