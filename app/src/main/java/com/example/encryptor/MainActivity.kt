package com.example.encryptor

import android.net.Uri
import androidx.activity.result.contract.ActivityResultContracts
import android.content.Context
import android.database.Cursor
import android.os.Bundle
import android.util.Log
import android.webkit.MimeTypeMap
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Button
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.documentfile.provider.DocumentFile
import com.example.encryptor.ui.theme.EncryptorTheme
import java.io.File
import java.io.FileOutputStream
import org.apache.commons.compress.archivers.tar.TarArchiveEntry
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream
import java.io.Closeable
import java.io.InputStream
import java.io.OutputStream

const val METADATA_FILENAME = ".encryptor"

data class IOStreams(
    val input: InputStream,
    val output: OutputStream
)


class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            EncryptorTheme {
                Main()
            }
        }
    }
}

@Composable
fun Main() {
    val context = LocalContext.current
    val contentResolver = context.contentResolver
    var password by remember { mutableStateOf("") }
    val selectedUri = remember { mutableStateOf<Uri?>(null) }

    val pickDocumentLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocumentTree()
    ) { uri -> uri?.let { selectedUri.value = uri } }

    Column {
        Spacer(modifier = Modifier.height(40.dp))
        Row {
            FilledTonalButton(
                onClick = {
                    pickDocumentLauncher.launch(null)
                },
                modifier = Modifier.size(200.dp)
            ) {
                Text("Pick a file")
            }
            Spacer(modifier = Modifier.width(20.dp))

            val text = "Selected folder:\n"
            val dirName = getSelectedDirName(selectedUri.value, context) ?: "None"
            Text(text + dirName)
        }

        Spacer(modifier = Modifier.height(40.dp))

        Row {
            Button(
                onClick = {
                    try {
                        encryptButtonHandler(selectedUri.value, password, context)
                    } catch (e: Exception) {
                        // TODO: Inform the user.
                        Log.e("UnexpectedError", "An unexpected error occurred", e)
                    }
                          },
                modifier = Modifier.size(150.dp)
            ) {
                Text("Encrypt")

            }
            Spacer(modifier = Modifier.width(40.dp))
            Button(
                onClick = {
                    try {
                        decryptButtonHandler(selectedUri.value, password, context)
                    } catch (e: Exception) {
                        // TODO: Inform the user.
                        Log.e("UnexpectedError", "An unexpected error occurred", e)
                    }
                          },
                modifier = Modifier.size(150.dp)
            ) {
                Text("Decrypt")
            }
        }

        Spacer(modifier = Modifier.height(40.dp))

        TextField(
            value = password,
            onValueChange = { password = it },
            label = { Text("Password") },
            visualTransformation = PasswordVisualTransformation()
        )
    }

}


// <R> defines a generic type parameter.
fun <R> useIOStreams(
    inputUri: Uri,
    outputUri: Uri,
    context: Context,
    block: (IOStreams) -> R   // Defines a lambda inside { IO -> R }.
): R? {
    val contentResolver = context.contentResolver

    fun openStream(uri: Uri, isInput: Boolean): Closeable? {
        return try {
            if (isInput) contentResolver.openInputStream(uri)
            else contentResolver.openOutputStream(uri)
        } catch (e: Exception) {
            val stream = if (isInput) "InputStream" else "OutputStream"
            Log.e("IOStreamError", "Exception while opening $stream for URI: \"$uri\"", e)
            null
        }
    }

    val inputStream = openStream(inputUri, true) as? InputStream
    val outputStream = openStream(outputUri, false) as? OutputStream

    if (inputStream == null || outputStream == null) {
        try {
            inputStream?.close()
            outputStream?.close()
        } catch (e: Exception) {
            Log.e("IOStreamError", "Failed to close stream", e)
        }
        return null
    }

    return try {
        inputStream.use { inStream ->
            outputStream.use { outStream ->
                block(IOStreams(inStream, outStream))  // Execute the lambda inside { I, O -> R }.
            }
        }
    } catch (e: Exception) {
        Log.e("IOStreamError", "Error during IO operations", e)
        null
    }
}


fun decryptButtonHandler(dirUri: Uri?, password: String, context: Context) {
    dirUri ?: return
    val dir = DocumentFile.fromTreeUri(context, dirUri)
    val encryptedDocumentFile: DocumentFile? =
        dir?.listFiles()?.singleOrNull { it.name?.endsWith(".tar.enc") == true }

    if (encryptedDocumentFile == null) {
        // TODO: Notify the user the directory isn't encrypted/is invalid.
        return
    }

    val originalTarName = encryptedDocumentFile.name?.removeSuffix(".enc") ?: "decrypted.tar"
    val decryptedTarDocumentFile = dir.createFile("application/x-tar", originalTarName)
    if (decryptedTarDocumentFile == null) {
        // TODO: Notify the user.
        Log.e("FileError", "Failed to create decrypted file: $originalTarName")
        return
    }
    val cryptoManager = CryptoManager()

    val isDecryptionSuccessful = useIOStreams(
        encryptedDocumentFile.uri,
        decryptedTarDocumentFile.uri,
        context
    ) { fileIOStreams ->
        cryptoManager.decryptStream(fileIOStreams, password)
    } ?: false

    if (!isDecryptionSuccessful) {
        // TODO: Notify the user.
        Log.e("Decryption", "Decryption failed.")
        if (!decryptedTarDocumentFile.delete()) {
            Log.e("FileError", "Failed to delete ${decryptedTarDocumentFile.name}")
        }
        return
    }

    Log.i("Decryption", "Decrypted successfully!")

    // TODO: Unarchive the decrypted file and delete the encrypted archive.
}


fun encryptButtonHandler(dirUri: Uri?, password: String, context: Context){
    dirUri ?: return

    val selectedRootDir = DocumentFile.fromTreeUri(context, dirUri)
    val metadataFile = selectedRootDir?.findFile(METADATA_FILENAME)
        ?: selectedRootDir?.createFile("text/plain", METADATA_FILENAME)
    val metadataFileUri = metadataFile?.uri

   if (metadataFileUri == null) {
       Log.e("MetadataFile", "Failed to read or create \"${METADATA_FILENAME}\".")
       return
   }

    val tarFile = createTarFile(dirUri, context) ?: return  // TODO: Log.e also.
    val encryptedTarFile = File(context.cacheDir, "${tarFile.name}.enc")
    if (encryptedTarFile.exists()) {
        encryptedTarFile.delete()
    }
    encryptedTarFile.createNewFile()

    val cryptoManager = CryptoManager()
    val tarFileUri = Uri.fromFile(tarFile)
    val encryptedTarFileUri = Uri.fromFile(encryptedTarFile)

    val isEncryptionSuccessful = useIOStreams(
        tarFileUri,
        encryptedTarFileUri,
        context
    ) { unencryptedIOStreams ->
        useIOStreams(
            metadataFileUri,
            metadataFileUri,
            context
        ) { metadataIOStreams ->
            cryptoManager.encryptStream(unencryptedIOStreams, metadataIOStreams, password)
        }
    } ?: false


    if (!isEncryptionSuccessful) {
        // TODO: Let the user know that nothing has been encrypted or changed.
        Log.e("Encryption", "Encryption failed.")
        return
    }

    Log.i("Encryption", "Encrypted successfully!")

    // Needed to open an output stream. It's never actually used.
    val dummyFile = File.createTempFile("dummy", ".tmp", context.cacheDir)
    val dummyUri = Uri.fromFile(dummyFile)

    val isIntegrityCheckPassed = useIOStreams(
        encryptedTarFileUri, dummyUri, context
    ) { fileIOStreams ->
        cryptoManager.decryptStream(
            fileIOStreams,
            password,
            true
        )
    } ?: false

    dummyFile.delete()

    if (isIntegrityCheckPassed) {
        Log.i("IntegrityCheck", "Integrity check passed successfully!")
        deleteAllFilesInDirUri(dirUri, context)
        // TODO: Consider what happens if copying fails.
        copyFileToDir(encryptedTarFile, dirUri, context)
    } else {
        // TODO: Let the user know that nothing has been encrypted or changed.
        Log.e("IntegrityCheck", "Integrity check failed.")
    }
}


fun getSelectedDirName(dirUri: Uri?, context: Context): String? {
    return dirUri?.let { uri ->
        return DocumentFile.fromTreeUri(context, uri)?.name ?: "Unknown"
    }
}


fun deleteAllFilesInDirUri(dirUri: Uri, context: Context) {
    val dir = DocumentFile.fromTreeUri(context, dirUri)
    dir?.listFiles()?.forEach { file ->
        file.delete()
    }
}


fun copyFileToDir(fileToCopy: File, destDirUri: Uri, context: Context) {
    val destinationDir = DocumentFile.fromTreeUri(context, destDirUri)
    val destinationFile = destinationDir?.createFile("application/octet-stream", fileToCopy.name) ?: return

    context.contentResolver.openOutputStream(destinationFile.uri)?.use { outputStream ->
        fileToCopy.inputStream().use { inputStream ->
            inputStream.copyTo(outputStream)
        }
    }
}


fun createTarFile(dirUri: Uri, context: Context): File? {
    val rootDir = DocumentFile.fromTreeUri(context, dirUri) ?: return null
    val tarName = getSelectedDirName(dirUri, context)!! + ".tar"
    val tarFile = File(context.filesDir, tarName)

    var keyAlias = ""
    TarArchiveOutputStream(FileOutputStream(tarFile)).use { tarOut ->
        addDirToTarArchive(rootDir, "", tarOut, context)
    }

    return tarFile
}


// FIXME: There are potential issues apparently. Ask chat.
fun addDirToTarArchive(
    dirToAdd: DocumentFile,
    relativePathPrefix: String,
    tarOut: TarArchiveOutputStream,
    context: Context
) {
    dirToAdd.listFiles().forEach { dirEntry ->

        val tarArchiveEntryName = "$relativePathPrefix${dirEntry.name}"
        val tarArchiveEntry = TarArchiveEntry(tarArchiveEntryName)

        if (dirEntry.isFile) {
            context.contentResolver.openInputStream(dirEntry.uri)?.use {
                tarArchiveEntry.size = it.available().toLong()
                tarOut.putArchiveEntry(tarArchiveEntry)
                it.copyTo(tarOut)
                tarOut.closeArchiveEntry()
            }
        } else {
            tarOut.putArchiveEntry(tarArchiveEntry)
            tarOut.closeArchiveEntry()
            // Recursively add all other files
            addDirToTarArchive(dirEntry, "$tarArchiveEntryName/", tarOut, context)
        }
    }
}


@Preview(showBackground = true)
@Composable
fun GreetingPreview() {
    EncryptorTheme {
        Main()
    }
}


fun displayQuery(cursor: Cursor?) {
    cursor?.use {
        val columnNames = it.columnNames.joinToString(", ")
        println("Columns: $columnNames")

        if (it.moveToFirst()) {
            for (i in 0 until it.columnCount) {
                val columnName = it.getColumnName(i)
                val columnValue = it.getString(i)
                println("$columnName: $columnValue")
            }
        }
    }
}


fun Uri.toFile(context: Context): File? {
    val inputStream = context.contentResolver.openInputStream(this)
    val extension = MimeTypeMap.getSingleton().getExtensionFromMimeType(context.contentResolver.getType(this))
    val tempFile = File.createTempFile("tmp", ".$extension")
    return try {
        tempFile.outputStream().use { fileOut ->
            inputStream?.copyTo(fileOut)
        }
        tempFile.deleteOnExit()
        tempFile
    } catch (e: Exception) {
        null
    }
}
