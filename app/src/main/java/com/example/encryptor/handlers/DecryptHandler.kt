package com.example.encryptor.handlers

import android.content.Context
import android.net.Uri
import android.util.Log
import androidx.documentfile.provider.DocumentFile
import com.example.encryptor.io.openIOStreamFromUris
import com.example.encryptor.tar.extractTarToDirectory
import com.example.encryptor.io.*
import com.example.encryptor.util.*
import com.example.encryptor.crypto.*

fun decryptButtonHandler(dirUri: Uri?, password: String?, context: Context) {
    dirUri ?: return
    val dir = DocumentFile.fromTreeUri(context, dirUri)
    val encryptedDocumentFile: DocumentFile =
        dir?.listFiles()?.singleOrNull { it.name?.endsWith(".tar.enc") == true }
            ?: return  // TODO: Notify the user the directory isn't encrypted/is invalid.

    val originalTarName = encryptedDocumentFile.name?.removeSuffix(".enc") ?: "decrypted.tar"
    val decryptedTarDocumentFile = dir.createFile("application/x-tar", originalTarName)
    if (decryptedTarDocumentFile == null) {
        // TODO: Notify the user.
        Log.e("FileError", "Failed to create decrypted file: $originalTarName")
        return
    }
    val cryptoManager = CryptoManager()
    val inputOutputFileUris = IOFileUris(encryptedDocumentFile.uri, decryptedTarDocumentFile.uri)

    // TODO: Create a function (same thing is done in encrypt handler).
    val selectedRootDir = DocumentFile.fromTreeUri(context, dirUri)
    val metadataFile = selectedRootDir?.findFile(METADATA_FILENAME)
        ?: selectedRootDir?.createFile("application/octet-stream", METADATA_FILENAME)
    val metadataFileUri = metadataFile?.uri

    val isBiometricUnlock = metadataFileUri != null

    val isDecryptionSuccessful = openIOStreamFromUris(
        inputOutputFileUris,
        context
    ) { fileIOStreams ->
        if (isBiometricUnlock) {
            openIOStreamFromUris(
                IOFileUris(metadataFileUri!!, metadataFileUri),
                context
            ) { metadataIOStreams ->
                cryptoManager.decryptStream(fileIOStreams, metadataIOStreams, password)
            }
        } else {
            cryptoManager.decryptStream(fileIOStreams, null, password)
        }
    } ?: false

    if (isDecryptionSuccessful) {
        Log.i("Decryption", "Decrypted successfully!")
        encryptedDocumentFile.delete()
    } else {
        // TODO: Notify the user.
        Log.e("Decryption", "Decryption failed.")
        if (!decryptedTarDocumentFile.delete()) {
            Log.e("FileError", "Failed to delete ${decryptedTarDocumentFile.name}")
        }
        return
    }

    val extractionSuccessful = extractTarToDirectory(
        decryptedTarDocumentFile.uri,
        dir,
        context
    )

    if (extractionSuccessful) {
        Log.i("Decryption", "Extracted successfully!")
        decryptedTarDocumentFile.delete()
    } else {
        Log.e("Decryption", "Extraction failed")
    }
}
