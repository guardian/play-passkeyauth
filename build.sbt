val playVersion = "3.0.8"

lazy val root = project
  .in(file("."))
  .settings(
    name := "play-passkeyauth",
    version := "0.1.0-SNAPSHOT",
    scalaVersion := "3.3.6",
    scalafmtOnCompile := true,
    libraryDependencies ++= Seq(
      "org.playframework" %% "play" % playVersion,
      "com.webauthn4j" % "webauthn4j-core" % "0.29.4.RELEASE",
      "org.playframework" %% "play-test" % playVersion % Test,
      "org.scalatestplus.play" %% "scalatestplus-play" % "7.0.2" % Test,
      "com.fasterxml.jackson.module" %% "jackson-module-scala" % "2.19.2" % Runtime
    )
  )
