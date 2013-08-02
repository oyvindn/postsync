package no.posten.dpost.sync

import dispatch._
import net.liftweb.json.DefaultFormats
import scalaz._
import Scalaz._
import net.liftweb.json.JsonParser
import java.io.File
import java.io.OutputStream
import org.apache.commons.io.FileUtils
import org.apache.commons.io.IOUtils
import java.io.InputStream
import dispatch.mime.Mime._
import javax.swing.JOptionPane
import no.posten.dpost.sync.OAuth.{AccessToken, AuthorisationCodeToken}

object API {
  sealed trait Resource {
    val link: List[Link]

    def links: List[Link] = link
    def link(relation: String) = links.find(_.rel.endsWith(relation))
  }

  case class Link(val rel: String, val uri: String, val `media-type`: String)
  object Link {
    def apply(uri: String) = new Link(null, uri, null)
  }

  case class EntryPoint(csrfToken: String, val link: List[Link], val primaryAccount: Account) extends Resource

  case class Accounts(val account: List[Account])
  case class Account(val fullName: String, val link: List[Link]) extends Resource
  case class Documents(val document: List[Document])
  case class Document(val subject: String, val creatorName: String, val fileType: String, val link: List[Link]) extends Resource {
    def id = link("self").get.uri
    def downloadLink = link("get_document_content").get
    def filename = subject + (if (Option(fileType).isDefined) "." + fileType else "")
  }

  implicit val formats = DefaultFormats // Brings in default date formats etc.

  val baseUrl = "https://qa.digipost.no/post"
  lazy val privateEntryUrl = baseUrl + "/api"
  lazy val privateEntryLink = Link(privateEntryUrl)

  val http = new Http with thread.Safety

  final val DigipostJsonV2 = "application/vnd.digipost-v2+json"
  final val UrlEncodedFormData = "application/x-www-form-urlencoded"

  def GET[T: Manifest](link: Link, accessToken: AccessToken) = {
    val headers = Map("Accept" -> DigipostJsonV2, "Authorization" -> ("Bearer " + accessToken.access_token))
    Control.trap {
      http(url(link.uri) <:< headers >- { json =>
        JsonParser.parse(json).extract[T]
      })
    }
  }

  def download(link: Link, toFile: File, accessToken: AccessToken) = {
    val writeToStream: OutputStream => InputStream => Unit = out => (in => IOUtils.copy(in, out))
    val headers = Map("Accept" -> DigipostJsonV2, "Authorization" -> ("Bearer " + accessToken.access_token))
    for {
      toStream <- Control.trap(FileUtils.openOutputStream(toFile))
      _ <- Control.trapAndFinally(http(url(link.uri).gzip <:< headers >> writeToStream(toStream)))(toStream.close)
    } yield ()
  }

  def upload(createLink: Link, token: String, subject: String, file: File, accessToken: AccessToken) = {
    val parameters = Map("subject" -> subject, "token" -> token)
    val headers = Map("Authorization" -> ("Bearer " + accessToken.access_token))
    for {
      fromStream <- Control.trap(FileUtils.openInputStream(file))
      location <- Control.trapAndFinally {
        http(url(createLink.uri) << parameters <:< headers <<* ("file", file.getName, () => fromStream) >:> {
          _.get("Location")
        })
      }(fromStream.close)
      resp <- if (location.isDefined) success(location.get.head) else failure()
    } yield resp
  }

}