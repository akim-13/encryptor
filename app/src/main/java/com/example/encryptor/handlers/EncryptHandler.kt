package com.example.encryptor.handlers

import android.content.Context
import android.net.Uri
import android.util.Log
import androidx.documentfile.provider.DocumentFile
import com.example.encryptor.tar.createTarFile
import com.example.encryptor.io.*
import com.example.encryptor.util.*
import com.example.encryptor.crypto.*
import java.io.File

// TODO: Disallow encrypting an already encrypted dir.
fun encryptButtonHandler(dirUri: Uri?, password: String, context: Context){
    dirUri ?: return

    val selectedRootDir = DocumentFile.fromTreeUri(context, dirUri)
    val metadataFile = selectedRootDir?.findFile(METADATA_FILENAME)
        ?: selectedRootDir?.createFile("application/octet-stream", METADATA_FILENAME)
    val metadataFileUri = metadataFile?.uri

    if (metadataFileUri == null) {
        Log.e("MetadataFile", "Failed to read or create \"$METADATA_FILENAME\".")
        return
    }

    val tarFile = createTarFile(dirUri, context, setOf(METADATA_FILENAME)) ?: return  // TODO: Log.e also.
    val encryptedTarFile = File(context.cacheDir, "${tarFile.name}.enc")
    if (encryptedTarFile.exists()) {
        encryptedTarFile.delete()
    }
    encryptedTarFile.createNewFile()

    val cryptoManager = CryptoManager()
    val tarFileUri = Uri.fromFile(tarFile)
    val encryptedTarFileUri = Uri.fromFile(encryptedTarFile)

    val isEncryptionSuccessful = openIOStreamFromUris(
        IOFileUris(tarFileUri, encryptedTarFileUri),
        context
    ) { fileIOStreams ->
        openIOStreamFromUris(
            IOFileUris(metadataFileUri, metadataFileUri),
            context
        ) { metadataIOStreams ->
            cryptoManager.encryptStream(fileIOStreams, metadataIOStreams, password)
        }
    } ?: false

    if (!isEncryptionSuccessful) {
        // TODO: Let the user know that nothing has been encrypted or changed.
        Log.e("Encryption", "Encryption failed.")
        return
    }

    Log.i("Encryption", "Encrypted successfully!")

    val isIntegrityCheckPassed = openIOStreamFromUris(
        IOFileUris(encryptedTarFileUri, null),
        context
    ) { fileIOStreams ->
        openIOStreamFromUris(
            IOFileUris(metadataFileUri, null),
            context
        ) { metadataIOStreams ->
            cryptoManager.decryptStream(fileIOStreams, metadataIOStreams, password, true)
        }
    } ?: false

    if (isIntegrityCheckPassed) {
        Log.i("IntegrityCheck", "Integrity check passed successfully!")
        deleteAllFilesInDirUri(dirUri, context, setOf(METADATA_FILENAME))
        // TODO: Copy first, delete everything but the encrypted archive afterwards.
        copyFileToDir(encryptedTarFile, dirUri, context)
    } else {
        // TODO: Let the user know that nothing has been encrypted or changed.
        Log.e("IntegrityCheck", "Integrity check failed.")
    }
}
