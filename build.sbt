import ReleaseTransformations.*
import sbtversionpolicy.withsbtrelease.ReleaseVersion

val playVersion = "3.0.9"

/*
 * To test whether any of these entries are redundant:
 * 1. Comment it out
 * 2. Run `sbt Runtime/dependencyList`
 * 3. If no earlier version appears in the dependency list, the entry can be removed.
 */
val safeTransitiveDependencies = Seq(
  "com.fasterxml.jackson.module" %% "jackson-module-scala" % "2.20.1" % Runtime
)

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
      "-release:11",
      "-Werror"
    ),
    scalafmtOnCompile := true,
    libraryDependencies ++= Seq(
      "org.playframework" %% "play" % playVersion,
      "com.webauthn4j" % "webauthn4j-core" % "0.30.0.RELEASE",
      "org.playframework" %% "play-test" % playVersion % Test,
      "org.scalatestplus.play" %% "scalatestplus-play" % "7.0.2" % Test,
      "com.gu.play-googleauth" %% "play-v30" % "29.1.0"
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
