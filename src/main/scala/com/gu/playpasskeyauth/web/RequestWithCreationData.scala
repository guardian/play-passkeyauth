package com.gu.playpasskeyauth.web

import play.api.libs.json.JsValue
import play.api.mvc.*
import play.api.mvc.Results.BadRequest

import scala.concurrent.{ExecutionContext, Future}

/** A request wrapper that carries passkey creation data along with the user and original request.
  *
  * This is used during passkey registration to pass the credential creation response from the browser's WebAuthn API
  * through the request processing chain.
  *
  * @tparam U
  *   The user type
  *
  * @tparam A
  *   The body content type (e.g., `AnyContent`, `JsValue`)
  *
  * @param passkeyName
  *   A human-readable name for this passkey credential, typically provided by the user. Examples: "Mac Chrome",
  *   "Apple keychain", "Yubikey"
 *
  * @param creationData
  *   The JSON response from `navigator.credentials.create()` in the browser. This contains the public key credential
  *   data needed to register the passkey.
 *
  * @param user
  *   The authenticated user registering the passkey
 *
  * @param request
  *   The original Play request being wrapped
  */
class RequestWithCreationData[U, A](
    val passkeyName: String,
    val creationData: JsValue,
    val user: U,
    request: Request[A]
) extends WrappedRequest[A](request)

/** Extractor for WebAuthn credential creation data from a request.
  *
  * Implementations define how to find the JSON data returned by `navigator.credentials.create()` in the browser. This
  * data is typically sent in the request body as JSON.
  *
  * @tparam R
  *   The request type (must be a subtype of Play's `Request`)
  *
  * @example
  *   {{{
  * // Extract creation data from a JSON request body
  * given CreationDataExtractor[[A] =>> RequestWithUser[MyUser, A]] with {
  *   def findCreationData[A](request: RequestWithUser[MyUser, A]): Option[JsValue] = {
  *     request.body match {
  *       case body: AnyContent => body.asJson.flatMap(json => (json \ "credential").toOption)
  *       case _ => None
  *     }
  *   }
  * }
  *
  * // The expected JSON structure from the browser:
  * // {
  * //   "credential": {
  * //     "id": "base64url-encoded-credential-id",
  * //     "rawId": "base64url-encoded-raw-id",
  * //     "type": "public-key",
  * //     "response": {
  * //       "clientDataJSON": "base64url-encoded-data",
  * //       "attestationObject": "base64url-encoded-data"
  * //     }
  * //   }
  * // }
  *   }}}
  */
trait CreationDataExtractor[R[_] <: Request[_]] {
  def findCreationData[A](request: R[A]): Option[JsValue]
}

/** Extractor for the passkey name from a request.
  *
  * Implementations define how to find the user-provided name for the passkey credential. This name helps users identify
  * their passkeys.
  *
  * @tparam R
  *   The request type (must be a subtype of Play's `Request`)
  */
trait PasskeyNameExtractor[R[_] <: Request[_]] {
  def findPasskeyName[A](request: R[A]): Option[String]
}

/** Action refiner that extracts passkey creation data and name from a [[RequestWithUser]].
  *
  * This action refiner is used during passkey registration to extract the credential creation response from the browser
  * and the user-provided passkey name. If either piece of data is missing, a `BadRequest` response is returned.
  *
  * @tparam U
  *   The user type
  *
  * @param creationDataExtractor
  *   Strategy for extracting the WebAuthn creation response JSON
 *
  * @param passkeyNameExtractor
  *   Strategy for extracting the user-provided passkey name
  */
class CreationDataAction[U](
    creationDataExtractor: CreationDataExtractor[[A] =>> RequestWithUser[U, A]],
    passkeyNameExtractor: PasskeyNameExtractor[[A] =>> RequestWithUser[U, A]]
)(using val executionContext: ExecutionContext)
    extends ActionRefiner[[A] =>> RequestWithUser[U, A], [A] =>> RequestWithCreationData[U, A]] {

  protected def refine[A](request: RequestWithUser[U, A]): Future[Either[Result, RequestWithCreationData[U, A]]] =
    (passkeyNameExtractor.findPasskeyName(request), creationDataExtractor.findCreationData(request)) match {
      case (Some(name), Some(jsValue)) =>
        Future.successful(
          Right(new RequestWithCreationData(name, jsValue, request.user, request))
        )
      case _ => Future.successful(Left(BadRequest("Expected creation data")))
    }
}
