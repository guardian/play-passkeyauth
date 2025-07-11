lazy val root = project
  .in(file("."))
  .settings(
    name := "play-passkeyauth",
    version := "0.1.0-SNAPSHOT",
    scalaVersion := "3.7.1",
    scalafmtOnCompile := true,
    libraryDependencies ++= Seq(
      "org.playframework" %% "play" % "3.0.8",
      "com.webauthn4j" % "webauthn4j-core" % "0.29.4.RELEASE",
      "org.scalameta" %% "munit" % "1.0.4" % Test
    )
  )
