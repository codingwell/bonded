val gitBuildNumber = run {
    val stdout = java.io.ByteArrayOutputStream()
    rootProject.exec {
        commandLine("git", "rev-list", "--count", "HEAD")
        standardOutput = stdout
    }
    stdout.toString().trim().toInt()
}

extra["gitBuildNumber"] = gitBuildNumber