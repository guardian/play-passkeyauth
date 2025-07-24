package com.gu.playpasskeyauth.model

import com.webauthn4j.data.client.Origin

import java.net.URI

case class HostApp(name: String, uri: URI) {
  val host = uri.getHost
  val origin = Origin.create(uri.toString)
}
