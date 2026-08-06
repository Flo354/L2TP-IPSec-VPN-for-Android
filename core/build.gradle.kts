import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlin.jvm)
}

// The whole L2TP/IPsec protocol stack lives here as a plain JVM library so that it can be
// exercised by fast, deterministic unit tests without an Android device. It must therefore
// never reference the Android SDK. Bytecode is pinned to Java 17 so that D8 can dex it.
java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

dependencies {
    testImplementation(libs.junit)
}

tasks.withType<Test>().configureEach {
    useJUnit()
    testLogging {
        events("failed")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
    // The end-to-end tests spin up real UDP sockets on loopback.
    systemProperty("java.net.preferIPv4Stack", "true")
}
