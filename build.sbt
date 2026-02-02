import ReleaseTransformations.*
import sbtversionpolicy.withsbtrelease.ReleaseVersion

val playVersion = "3.0.10"

/*
 * To test whether any of these entries are redundant:
 * 1. Comment it out
 * 2. Run `sbt Runtime/dependencyList`
 * 3. If no earlier version appears in the dependency list, the entry can be removed.
 */
val safeTransitiveDependencies = {
  val jacksonVersion = "2.21.0"
  Seq(
    "com.fasterxml.jackson.datatype" % "jackson-datatype-jdk8" % jacksonVersion % Runtime,
    "com.fasterxml.jackson.datatype" % "jackson-datatype-jsr310" % jacksonVersion % Runtime,
    "com.fasterxml.jackson.module" % "jackson-module-parameter-names" % jacksonVersion % Runtime,
    "com.fasterxml.jackson.module" %% "jackson-module-scala" % jacksonVersion % Runtime
  )
}

lazy val root = project
  .in(file("."))
  .settings(
    licenses := Seq(License.Apache2),
    organization := "com.gu",
    name := "play-passkeyauth",
    scalaVersion := "3.3.7",
    scalacOptions ++= Seq(
      "-deprecation",
      "-explain",
      "-no-indent",
      "-release:11",
      "-Werror"
    ),
    scalafmtOnCompile := true,
    libraryDependencies ++= Seq(
      "org.playframework" %% "play" % playVersion,
      "com.webauthn4j" % "webauthn4j-core" % "0.31.0.RELEASE",
      "org.playframework" %% "play-test" % playVersion % Test,
      "org.scalatestplus.play" %% "scalatestplus-play" % "7.0.2" % Test,
      "org.scalatestplus" %% "scalacheck-1-18" % "3.2.19.0" % Test
    ) ++ safeTransitiveDependencies,
    releaseVersion := ReleaseVersion.fromAggregatedAssessedCompatibilityWithLatestRelease().value,
    releaseProcess := Seq[ReleaseStep](
      checkSnapshotDependencies,
      inquireVersions,
      runClean,
      runTest,
      setReleaseVersion,
      commitReleaseVersion,
      tagRelease,
      setNextVersion,
      commitNextVersion
    )
  )
