package controllers

import play.api.mvc._

import javax.inject._

/** Simple home page controller demonstrating a basic passkey-protected application. */
@Singleton
class HomeController @Inject() (cc: ControllerComponents) extends AbstractController(cc) {

  def index(): Action[AnyContent] = Action { implicit request =>
    Ok(views.html.index())
  }
}
