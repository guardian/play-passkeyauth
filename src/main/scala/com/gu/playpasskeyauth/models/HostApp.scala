package com.gu.playpasskeyauth.models

import com.webauthn4j.data.client.Origin

import java.net.URI

case class HostApp(name: String, uri: URI) {
  val host: String = uri.getHost
  val origin: Origin = Origin.create(uri.toString)
}
