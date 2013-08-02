package no.posten.dpost.sync

import java.awt.Desktop
import java.net.URI
import javax.crypto
import crypto.spec.SecretKeySpec
import java.util.UUID
import javax.swing.JOptionPane
import dispatch.{url, thread, Http}
import org.apache.commons.codec.binary.Base64
import net.liftweb.json.{DefaultFormats, JsonParser}
import scalaz.{Failure, Success}

object OAuthSettings {
  final val ClientId = "***"
  final val Secret = "***"

  final val RedirectUrl = "https://qa.digipost.no"
  lazy val AuthorizeUrl = API.baseUrl + "/api/oauth/authorize/new?response_type=code&client_id=" + ClientId + "&state=" + Cryptography.randomNonce
  lazy val AccessTokenUrl = API.baseUrl + "/api/oauth/accesstoken"
}

object OAuthTest extends App {
  OAuth.authenticate()
}

object OAuth {

  implicit val formats = DefaultFormats

  case class AccessToken(access_token: String, refresh_token: String, expires_in: String, token_type: String, id_token: Option[String]) {
    def refreshToken = RefreshToken(refresh_token)
  }
  case class IdToken(aud: String, exp: String, user_id: String, iss: String, nonce: String)
  class Token
  case class RefreshToken(value: String) extends Token
  case class AuthorisationCodeToken(value: String) extends Token

  val http = new Http with thread.Safety

  def authenticate() = {
    Browser.openUrl(OAuthSettings.AuthorizeUrl)
    val code = JOptionPane.showInputDialog("OAuth code from server")
    init(AuthorisationCodeToken(code))
  }

  def init(token: AuthorisationCodeToken) = fetchAccessToken(token)

  def refreshAccessToken(token: RefreshToken) = fetchAccessToken(token)

  private def fetchAccessToken(token: Token): AccessToken = {
    val authentication = new String(Base64.encodeBase64((OAuthSettings.ClientId + ":" + OAuthSettings.Secret).getBytes))
    val nonce = Cryptography.randomNonce

    val grantParameters = token match {
      case AuthorisationCodeToken(code) => Seq("grant_type" -> "code", "code" -> code)
      case RefreshToken(token) =>  Seq("grant_type" -> "refresh_token", "refresh_token" -> token)
    }

    val defaultParams = Seq("redirect_uri" -> OAuthSettings.RedirectUrl, "nonce" -> nonce)
    val headers = Map("Content-Type" -> API.UrlEncodedFormData, "Authorization" -> ("Basic " + authentication))

    val result = Control.trap {
      http(url(OAuthSettings.AccessTokenUrl) << grantParameters ++ defaultParams  <:< headers >- { json =>
        JsonParser.parse(json).extract[AccessToken]
      })
    }

    val accessToken = result match {
      case Success(x: AccessToken) => x
      case Failure(e) => sys.error("Failed fetching access token: " + e)
    }

    token match {
      case AuthorisationCodeToken(_) => verifyInitialAccessToken(accessToken, nonce)
      case RefreshToken(_) => accessToken //TODO: check nonce?
    }

  }

  private def verifyInitialAccessToken(token: AccessToken, nonce: String): AccessToken = {
    def verify(Expected: String, actual: String, name: String) {
      actual match {
        case Expected => println("Id-token param " + name + " verified!")
        case _ => sys.error("Bad id-token param " + name)
      }
    }

    val idToken = token.id_token.getOrElse(sys.error("Missing id-token!")).split("\\.")
    val idTokenHash = idToken(0)
    val idTokenValue = idToken(1)

    verify(idTokenHash, Cryptography.signWithHmacSha256(idTokenValue, OAuthSettings.Secret), "id_token")

    val decodedIdTokenValue = new String(Base64.decodeBase64(idTokenValue))
    val idTokenObject = JsonParser.parse(decodedIdTokenValue).extract[IdToken]

    verify(OAuthSettings.ClientId, idTokenObject.aud, "audience")
    verify(nonce, idTokenObject.nonce, "nonce")

    token
  }
}

object Cryptography {
  def signWithHmacSha256(tokenValue: String, secret: String) = {
    val HmacSHA256 = "HmacSHA256"
    val key = new SecretKeySpec(secret.getBytes, HmacSHA256)
    val mac = crypto.Mac.getInstance(HmacSHA256)

    mac.init(key)
    new String(Base64.encodeBase64(mac.doFinal(tokenValue.getBytes)))
  }

  def randomNonce = UUID.randomUUID.toString
}

object Browser {
  def openUrl(url: String) {
    if (!java.awt.Desktop.isDesktopSupported) sys.error("Desktop not suported")

    val desktop = Desktop.getDesktop

    if (!desktop.isSupported(Desktop.Action.BROWSE)) sys.error("Unable to open default browser")

    desktop.browse(new URI(url))
  }
}
