package com.gu.playpasskeyauth.web

import play.api.libs.json.JsValue
import play.api.mvc.*
import play.api.mvc.Results.BadRequest

import scala.concurrent.{ExecutionContext, Future}

/** A request wrapper that carries passkey authentication data along with the user and original request.
  *
  * This is used during passkey authentication to pass the credential assertion response from the browser's WebAuthn API
  * through the request processing chain.
  *
  * @tparam U
  *   The user type
  *
  * @tparam A
  *   The body content type (e.g., `AnyContent`, `JsValue`)
  *
  * @param authenticationData
  *   The JSON response from `navigator.credentials.get()` in the browser. This contains the signed assertion data
  *   needed to verify the passkey.
  *
  * @param user
  *   The user attempting to authenticate
  *
  * @param request
  *   The original Play request being wrapped
  */
case class RequestWithAuthenticationData[U, A](
    authenticationData: JsValue,
    user: U,
    request: Request[A]
) extends WrappedRequest[A](request)

/** Extractor for WebAuthn authentication data from a request.
  *
  * Implementations define how to find the JSON data returned by `navigator.credentials.get()` in the browser. This data
  * is typically sent in the request body or as a header.
  *
  * @tparam R
  *   The request type (must be a subtype of Play's `Request`)
  *
  * @example
  *   {{{
  * // Extract authentication data from a JSON request body
  * given AuthenticationDataExtractor[[A] =>> RequestWithUser[MyUser, A]] with {
  *   def findAuthenticationData[A](request: RequestWithUser[MyUser, A]): Option[JsValue] = {
  *     request.body match {
  *       case body: AnyContent => body.asJson.flatMap(json => (json \ "assertion").toOption)
  *       case _ => None
  *     }
  *   }
  * }
  *
  * // Or extract from a custom header (if sending as base64-encoded JSON)
  * given AuthenticationDataExtractor[[A] =>> RequestWithUser[MyUser, A]] with {
  *   def findAuthenticationData[A](request: RequestWithUser[MyUser, A]): Option[JsValue] = {
  *     request.headers.get("X-Passkey-Assertion")
  *       .map(base64 => Json.parse(Base64.getDecoder.decode(base64)))
  *   }
  * }
  *   }}}
  */
trait AuthenticationDataExtractor[R[_] <: Request[_]] {
  def findAuthenticationData[A](request: R[A]): Option[JsValue]
}

/** Action refiner that extracts passkey authentication data from a [[RequestWithUser]].
  *
  * This action refiner is used during passkey authentication to extract the credential assertion response from the
  * browser. If the authentication data is missing, a `BadRequest` response is returned.
  *
  * @tparam U
  *   The user type
  *
  * @param authDataExtractor
  *   Strategy for extracting the WebAuthn assertion response JSON
  *
  * @param executionContext
  *   The execution context for async operations
  */
class AuthenticationDataAction[U](
    authDataExtractor: AuthenticationDataExtractor[[A] =>> RequestWithUser[U, A]]
)(using val executionContext: ExecutionContext)
    extends ActionRefiner[[A] =>> RequestWithUser[U, A], [A] =>> RequestWithAuthenticationData[U, A]] {

  protected def refine[A](request: RequestWithUser[U, A]): Future[Either[Result, RequestWithAuthenticationData[U, A]]] =
    authDataExtractor.findAuthenticationData(request) match {
      case Some(jsValue) =>
        Future.successful(
          Right(RequestWithAuthenticationData(jsValue, request.user, request))
        )
      case None => Future.successful(Left(BadRequest("Expected authentication data")))
    }
}
