plugins {
    id("java-library")
}

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}

dependencies {
    implementation(fileTree(mapOf("dir" to "libs", "include" to listOf("*.jar"))))
}

tasks.jar {
    manifest {
        attributes["Main-Class"] = "com.skyguild.javapush.Main" // Replace with your actual main class
    }
    archiveFileName.set("server.jar") // Name of your output JAR file

    from(sourceSets.main.get().output) // Include compiled classes
    from(configurations.runtimeClasspath.get().map {
        if (it.isDirectory) it else zipTree(it)
    })

    duplicatesStrategy = DuplicatesStrategy.EXCLUDE // Handle duplicate files

    exclude("META-INF/*.RSA", "META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.MF")
    //
}