val playVersion = "3.0.8"

lazy val root = project
  .in(file("."))
  .settings(
    licenses := Seq(License.Apache2),
    organization := "com.gu",
    name := "play-passkeyauth",
//    version := "0.1.0-SNAPSHOT",
    version := "0.1.2-SNAPSHOT",
    scalaVersion := "3.3.6",
    scalacOptions ++= Seq("-deprecation", "-explain", "-Werror"),
    scalafmtOnCompile := true,
    libraryDependencies ++= Seq(
      "org.playframework" %% "play" % playVersion,
      "com.webauthn4j" % "webauthn4j-core" % "0.29.5.RELEASE",
      "org.playframework" %% "play-test" % playVersion % Test,
      "org.scalatestplus.play" %% "scalatestplus-play" % "7.0.2" % Test,
      "com.fasterxml.jackson.module" %% "jackson-module-scala" % "2.19.2" % Runtime
    )
  )
