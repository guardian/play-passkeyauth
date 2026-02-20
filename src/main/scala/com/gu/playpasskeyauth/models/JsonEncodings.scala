package com.gu.playpasskeyauth.models

import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.databind.module.SimpleModule
import com.fasterxml.jackson.databind.{JsonSerializer, ObjectMapper, SerializerProvider}
import com.webauthn4j.data.client.challenge.DefaultChallenge
import com.webauthn4j.data.{
  PublicKeyCredentialCreationOptions,
  PublicKeyCredentialDescriptor,
  PublicKeyCredentialRequestOptions,
  PublicKeyCredentialUserEntity
}
import com.webauthn4j.util.Base64UrlUtil
import play.api.libs.json.*

/** JSON encoding utilities for WebAuthn/passkey data structures.
  *
  * This object provides conversion methods between Java objects (from WebAuthn4j library), Jackson JSON, and Play JSON.
  * The WebAuthn4j library uses Jackson annotations, so we leverage Jackson's ObjectMapper for serialization with custom
  * serializers to ensure the output matches the WebAuthn specification requirements.
  */
object JsonEncodings {

  // Play JSON Writes for controller responses
  given Writes[PublicKeyCredentialCreationOptions] = Writes { options =>
    toPlayJson(options)
  }

  given Writes[PublicKeyCredentialRequestOptions] = Writes { options =>
    toPlayJson(options)
  }

  given Writes[Unit] = Writes { _ => JsNull }

  given Writes[Passkey] = Writes { passkey =>
    Json.obj(
      "id" -> passkey.id.toBase64Url,
      "name" -> passkey.name.value,
      "createdAt" -> passkey.createdAt.toEpochMilli,
      "lastUsedAt" -> passkey.lastUsedAt.map(_.toEpochMilli)
    )
  }

  /** Convert any object to a JSON string using Jackson.
    *
    * This is useful for serializing WebAuthn4j objects that have Jackson annotations.
    *
    * @param obj
    *   The object to serialize
    * @return
    *   JSON string representation
    */
  def toJson(obj: Any): String = mapper.writeValueAsString(obj)

  /** Convert any object to Play JSON.
    *
    * This first converts to a Jackson JSON string, then parses it as Play JSON.
    *
    * @param obj
    *   The object to serialize
    * @return
    *   Play JSON value
    */
  def toPlayJson(obj: Any): JsValue = Json.parse(toJson(obj))

  /** Parse a JSON string to a specific type using Jackson.
    *
    * @param json
    *   The JSON string to parse
    * @param clazz
    *   The target class type
    * @tparam T
    *   The type to deserialize to
    * @return
    *   Deserialized object
    */
  def fromJson[T](json: String, clazz: Class[T]): T =
    mapper.readValue(json, clazz)

  /** Jackson ObjectMapper configured for WebAuthn/passkey serialization.
    *
    * This mapper includes custom serializers to ensure WebAuthn data structures are serialized according to the
    * WebAuthn specification (e.g., base64url encoding for binary data).
    */
  private val mapper: ObjectMapper = {
    val mapper = new ObjectMapper()
    val module = new SimpleModule()

    // Custom serializer for Challenge - serialize as base64url string instead of nested object
    // The WebAuthn spec expects challenge to be a base64url-encoded string
    module.addSerializer(
      classOf[DefaultChallenge],
      new JsonSerializer[DefaultChallenge] {
        override def serialize(
            challenge: DefaultChallenge,
            gen: JsonGenerator,
            serializers: SerializerProvider
        ): Unit =
          gen.writeString(Base64UrlUtil.encodeToString(challenge.getValue))
      }
    )

    // Custom serializer for PublicKeyCredentialUserEntity - encode user ID as base64url
    // The WebAuthn spec requires user.id to be base64url-encoded
    module.addSerializer(
      classOf[PublicKeyCredentialUserEntity],
      new JsonSerializer[PublicKeyCredentialUserEntity] {
        override def serialize(
            user: PublicKeyCredentialUserEntity,
            gen: JsonGenerator,
            serializers: SerializerProvider
        ): Unit = {
          gen.writeStartObject()
          gen.writeStringField("id", Base64UrlUtil.encodeToString(user.getId))
          gen.writeStringField("name", user.getName)
          gen.writeStringField("displayName", user.getDisplayName)
          gen.writeEndObject()
        }
      }
    )

    // Custom serializer for PublicKeyCredentialDescriptor - encode credential ID as base64url
    // The WebAuthn spec requires credential IDs to be base64url-encoded
    module.addSerializer(
      classOf[PublicKeyCredentialDescriptor],
      new JsonSerializer[PublicKeyCredentialDescriptor] {
        override def serialize(
            descriptor: PublicKeyCredentialDescriptor,
            gen: JsonGenerator,
            serializers: SerializerProvider
        ): Unit = {
          gen.writeStartObject()
          gen.writeStringField("type", descriptor.getType.getValue)
          gen.writeStringField(
            "id",
            Base64UrlUtil.encodeToString(descriptor.getId)
          )
          if (descriptor.getTransports != null) {
            gen.writeArrayFieldStart("transports")
            descriptor.getTransports.forEach(transport => gen.writeString(transport.getValue))
            gen.writeEndArray()
          }
          gen.writeEndObject()
        }
      }
    )
    mapper.registerModule(module)
    mapper
  }
}
