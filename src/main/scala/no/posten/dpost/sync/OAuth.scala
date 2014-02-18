package no.posten.dpost.sync

object OAuthTest extends App {
  val accessToken = OAuth.authenticate()
}

object OAuthSettings {
  final val ClientId = "***"
  final val Secret = "***"

  final val RedirectUrl = "https://qa.digipost.no"
  lazy val AuthorizeUrl = API.baseUrl + "/api/oauth/authorize/new?response_type=code&client_id=" + ClientId + "&state=" + Cryptography.randomNonce
  lazy val AccessTokenUrl = API.baseUrl + "/api/oauth/accesstoken"
}

object OAuth {
  import dispatch.{url, thread, Http}
  import net.liftweb.json.{DefaultFormats, JsonParser}
  import scalaz.{Failure, Success}
  import javax.swing.JOptionPane

  implicit val formats = DefaultFormats

  case class AccessToken(access_token: String, refresh_token: String, expires_in: String, token_type: String, id_token: Option[String]) {
    def refreshToken = RefreshToken(refresh_token)
  }
  case class IdToken(aud: String, exp: String, user_id: String, iss: String, nonce: String)
  sealed trait Token
  case class RefreshToken(value: String) extends Token
  case class AuthorisationCodeToken(value: String) extends Token

  val http = new Http with thread.Safety

  def authenticate(): AccessToken = {
    Browser.openUrl(OAuthSettings.AuthorizeUrl)
    val code = JOptionPane.showInputDialog("OAuth code from server")
    fetchInitialAccessToken(AuthorisationCodeToken(code))
  }

  def fetchInitialAccessToken(token: AuthorisationCodeToken) = fetchAccessToken(token)
  def refreshAccessToken(token: RefreshToken) = fetchAccessToken(token)

  private def fetchAccessToken(token: Token): AccessToken = {
    val authentication = Cryptography.encodeBase64(OAuthSettings.ClientId + ":" + OAuthSettings.Secret)
    val nonce = Cryptography.randomNonce

    val grantParameters = token match {
      case AuthorisationCodeToken(authCode) => Seq("grant_type" -> "code", "code" -> authCode)
      case RefreshToken(refreshToken) =>  Seq("grant_type" -> "refresh_token", "refresh_token" -> refreshToken)
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
      case RefreshToken(_) => accessToken
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

    val decodedIdTokenValue = Cryptography.decodeBase64(idTokenValue)
    val idTokenObject = JsonParser.parse(decodedIdTokenValue).extract[IdToken]

    verify(OAuthSettings.ClientId, idTokenObject.aud, "audience")
    verify(nonce, idTokenObject.nonce, "nonce")

    token
  }
}

object Cryptography {
  import javax.crypto
  import crypto.spec.SecretKeySpec
  import java.util.UUID
  import org.apache.commons.codec.binary.Base64

  def signWithHmacSha256(tokenValue: String, secret: String) = {
    val HmacSHA256 = "HmacSHA256"
    val key = new SecretKeySpec(secret.getBytes, HmacSHA256)
    val mac = crypto.Mac.getInstance(HmacSHA256)

    mac.init(key)
    new String(Base64.encodeBase64(mac.doFinal(tokenValue.getBytes)))
  }

  def encodeBase64(value: String) = new String(Base64.encodeBase64(value.getBytes))
  def decodeBase64(encoded: String) = new String(Base64.decodeBase64(encoded))

  def randomNonce = UUID.randomUUID.toString
}

object Browser {
  import java.awt.Desktop
  import java.net.URI

  def openUrl(url: String) {
    if (!java.awt.Desktop.isDesktopSupported) sys.error("Desktop not suported")

    val desktop = Desktop.getDesktop

    if (!desktop.isSupported(Desktop.Action.BROWSE)) sys.error("Unable to open default browser")

    desktop.browse(new URI(url))
  }
}
