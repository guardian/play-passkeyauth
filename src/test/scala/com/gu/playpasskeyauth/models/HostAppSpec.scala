package com.gu.playpasskeyauth.models

import org.scalacheck.Gen
import org.scalatest.flatspec.AnyFlatSpec
import org.scalatest.matchers.should.Matchers
import org.scalatestplus.scalacheck.ScalaCheckPropertyChecks

import java.net.URI

class HostAppSpec extends AnyFlatSpec with Matchers with ScalaCheckPropertyChecks {

  import HostAppSpec.*

  "HostApp" should "reject empty name" in {
    val exception = intercept[IllegalArgumentException] {
      HostApp("", new URI("https://example.com"))
    }
    exception.getMessage should include("name must not be empty")
  }

  it should "reject whitespace-only name" in {
    val exception = intercept[IllegalArgumentException] {
      HostApp("   ", new URI("https://example.com"))
    }
    exception.getMessage should include("name must not be empty")
  }

  it should "accept non-empty name" in {
    val app = HostApp("My App", new URI("https://example.com"))
    app.name shouldBe "My App"
  }

  it should "accept any non-empty trimmed name" in {
    forAll(genNonEmptyName) { name =>
      val app = HostApp(name, new URI("https://example.com"))
      app.name shouldBe name
    }
  }

  it should "reject URI without host" in {
    val exception = intercept[IllegalArgumentException] {
      HostApp("My App", new URI("file:///path/to/file"))
    }
    exception.getMessage should include("valid host")
  }

  it should "extract host from URI" in {
    val app = HostApp("My App", new URI("https://example.com"))
    app.host shouldBe "example.com"
  }

  it should "extract host from URI with port" in {
    val app = HostApp("My App", new URI("https://example.com:8443"))
    app.host shouldBe "example.com"
  }

  it should "extract host from URI with path" in {
    val app = HostApp("My App", new URI("https://example.com/some/path"))
    app.host shouldBe "example.com"
  }

  it should "extract localhost as host" in {
    val app = HostApp("My App", new URI("http://localhost:9000"))
    app.host shouldBe "localhost"
  }

  it should "accept https scheme" in {
    val app = HostApp("My App", new URI("https://example.com"))
    app.uri.getScheme shouldBe "https"
  }

  it should "reject http scheme for non-localhost" in {
    val exception = intercept[IllegalArgumentException] {
      HostApp("My App", new URI("http://example.com"))
    }
    exception.getMessage should include("https")
  }

  it should "accept http scheme for localhost" in {
    val app = HostApp("My App", new URI("http://localhost:9000"))
    app.uri.getScheme shouldBe "http"
  }

  it should "accept http scheme for localhost without port" in {
    val app = HostApp("My App", new URI("http://localhost"))
    app.host shouldBe "localhost"
  }

  it should "reject http for any non-localhost host" in {
    forAll(genNonLocalhostDomain) { domain =>
      val exception = intercept[IllegalArgumentException] {
        HostApp("My App", new URI(s"http://$domain"))
      }
      exception.getMessage should include("https")
    }
  }

  it should "accept https for any valid domain" in {
    forAll(genValidDomain) { domain =>
      val app = HostApp("My App", new URI(s"https://$domain"))
      app.host shouldBe domain
    }
  }

  it should "create origin from https URI" in {
    val app = HostApp("My App", new URI("https://example.com"))
    app.origin.toString shouldBe "https://example.com"
  }

  it should "create origin from https URI with port" in {
    val app = HostApp("My App", new URI("https://example.com:8443"))
    app.origin.toString shouldBe "https://example.com:8443"
  }

  it should "create origin from http localhost URI" in {
    val app = HostApp("My App", new URI("http://localhost:9000"))
    app.origin.toString shouldBe "http://localhost:9000"
  }
}

object HostAppSpec {

  /** Generator for non-empty names */
  val genNonEmptyName: Gen[String] =
    Gen.alphaStr.suchThat(_.trim.nonEmpty)

  /** Generator for valid domain names */
  val genValidDomain: Gen[String] = for {
    subdomain <- Gen.option(Gen.nonEmptyListOf(Gen.alphaNumChar).map(cs => s"${cs.mkString}."))
    domain <- Gen.alphaLowerStr.suchThat(s => s.nonEmpty && s.length >= 2)
    tld <- Gen.oneOf("com", "org", "net", "io", "co.uk")
  } yield s"${subdomain.getOrElse("")}$domain.$tld"

  /** Generator for non-localhost domains */
  val genNonLocalhostDomain: Gen[String] =
    genValidDomain.suchThat(_ != "localhost")
}
