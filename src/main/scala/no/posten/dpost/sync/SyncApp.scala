package no.posten.dpost.sync

import java.io.File
import Sync._
import org.apache.commons.io.IOUtils
import org.apache.commons.io.FileUtils
import scala.io.Source
import scalaz._
import Scalaz._
import API._

object SyncApp extends App {
  def getMessages(account: Account, rel: String) = {
    val documentsLink = account.link(rel).get
    GET[Documents](documentsLink, accessToken) map (_.document)
  }

  val syncFolder = new File("/tmp/sync")
  if (!syncFolder.exists) syncFolder.mkdir()
  val syncFile = new File(syncFolder, ".sync")
  if (!syncFile.exists) syncFile.createNewFile()
  val localSyncData = readSyncFile(syncFile)

  val accessToken = OAuth.authenticate()

  val entryPointResult = for {
    entryPoint <- GET[EntryPoint](privateEntryLink, accessToken)
  } yield entryPoint

  val entryPoint = entryPointResult.fold(err => sys.error(err), identity)

  val documentResult = for {
    archive <- getMessages(entryPoint.primaryAccount, "document_archive")
  } yield archive

  val documents = documentResult | List()
  val remoteSyncData = documents.map(doc => SyncItem(doc))
  val deletedRemote = findItemsNotIn(localSyncData, remoteSyncData)
  val deleted = delete(syncFolder, deletedRemote)
  val localSyncDataAfterDelete = localSyncData -- deleted
  val newRemote = findItemsNotIn(remoteSyncData, localSyncDataAfterDelete)
  val downloaded = Sync.download(syncFolder, newRemote, accessToken)
  val localSyncDataAfterDownload = localSyncDataAfterDelete ++ downloaded
  val newFiles = findFilesNotIn(syncFolder, localSyncDataAfterDownload, List(".sync", ".DS_Store"))

  val uploadLink = entryPoint.primaryAccount.link("upload_document").get
  val uploadedFiles = Sync.upload(uploadLink, entryPoint.csrfToken, newFiles, accessToken)
  val localSyncDataAfterUpload = localSyncDataAfterDownload ++ uploadedFiles

  writeSyncFile(syncFile, localSyncDataAfterUpload)

}