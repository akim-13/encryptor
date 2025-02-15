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
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.documentfile.provider.DocumentFile
import com.example.encryptor.ui.theme.EncryptorTheme
import java.io.File
import java.io.FileOutputStream
import org.apache.commons.compress.archivers.tar.TarArchiveEntry
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream
import java.io.Closeable
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.util.UUID

const val METADATA_FILENAME = ".encryptor"

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
                onClick = { encryptButtonHandler(selectedUri.value, context) },
                modifier = Modifier.size(150.dp)
            ) {
                Text("Encrypt")

            }
            Spacer(modifier = Modifier.width(40.dp))
            Button(
                onClick = {decryptButtonHandler(selectedUri.value, context)},
                modifier = Modifier.size(150.dp)
            ) {
                Text("Decrypt")
            }
        }
    }
}

fun decryptButtonHandler(dirUri: Uri?, context: Context) {
    dirUri ?: return
    val dir = DocumentFile.fromTreeUri(context, dirUri)
    val encryptedDocumentFile: DocumentFile? =
        dir?.listFiles()?.singleOrNull { it.name?.endsWith(".tar.enc") == true }

    if (encryptedDocumentFile == null) {
        // TODO: Notify the user the directory isn't encrypted/is invalid.
        return
    }

    val originalTarName = encryptedDocumentFile.name?.removeSuffix(".enc") ?: "decrypted.tar"
    // TODO: Notify the user.
    val decryptedTarDocumentFile = dir.createFile("application/x-tar", originalTarName)
    if (decryptedTarDocumentFile == null) {
        Log.e("FileError", "Failed to create decrypted file: $originalTarName")
        return
    }
    val cryptoManager = CryptoManager()

    val isDecryptionSuccessful = useIOStreams(
        encryptedDocumentFile.uri, decryptedTarDocumentFile.uri, context
    ) { encryptedInputStream, decryptedOutputStream ->
        // FIXME: Extract key alias from encrypted tar header.
        val keyAlias = ""
        cryptoManager.decryptFile(encryptedInputStream, keyAlias, decryptedOutputStream)
    } ?: false

    if (!isDecryptionSuccessful) {
        // TODO: Notify the user.
        println("Faaaaaaaaaaaaaaaaaaaaaaaaaaaaaail")
        if (!decryptedTarDocumentFile.delete()) {
            Log.e("FileError", "Failed to delete ${decryptedTarDocumentFile.name}")
        }
        return
    }
}

// <R> defines a generic type parameter.
fun <R> useIOStreams(
    inputUri: Uri,
    outputUri: Uri,
    context: Context,
    block: (InputStream, OutputStream) -> R // Defines a lambda inside { I, O -> R }.
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
                block(inStream, outStream) // Execute the lambda inside { I, O -> R }.
            }
        }
    } catch (e: Exception) {
        Log.e("IOStreamError", "Error during IO operations", e)
        null
    }
}


fun encryptButtonHandler(dirUri: Uri?, context: Context){
    dirUri ?: return
    val (tarFile, keyAlias) = createTarAndGetKeyAlias(dirUri, context) ?: return
    val tarFileUri = Uri.fromFile(tarFile)
    val encryptedTarFile = File(context.cacheDir, "${tarFile.name}.enc")
    if (encryptedTarFile.exists()) {
        encryptedTarFile.delete()
    }
    encryptedTarFile.createNewFile()

    val cryptoManager = CryptoManager()
    cryptoManager.encryptFile(tarFileUri, context, keyAlias, encryptedTarFile)

    if (cryptoManager.isIntegrityCheckPassed(encryptedTarFile, keyAlias)) {
        deleteAllFilesInDirUri(dirUri, context)
        copyFileToDir(encryptedTarFile, dirUri, context)
    } else {
        // TODO: Let the user know that nothing has been encrypted or changed.
    }

    context.filesDir.listFiles()?.forEach { file ->
        println("INTERNAL STORAGE CONTENT:${file.name}")
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

fun createTarAndGetKeyAlias(dirUri: Uri, context: Context): Pair<File, String>? {
    val rootDir = DocumentFile.fromTreeUri(context, dirUri) ?: return null
    val tarName = getSelectedDirName(dirUri, context)!! + ".tar"
    val tarFile = File(context.filesDir, tarName)

    var keyAlias = ""
    TarArchiveOutputStream(FileOutputStream(tarFile)).use { tarOut ->
        // TODO: make this global or smth, this is a hack.
        keyAlias = addDirToTarAndGetKeyAlias(rootDir, "", tarOut, context) ?: UUID.randomUUID().toString()
    }

    if (keyAlias == "") throw Exception("This shouldn't have happened")

    return Pair(tarFile, keyAlias)
}

fun addDirToTarAndGetKeyAlias(
    dir: DocumentFile,
    base: String,
    tarOut: TarArchiveOutputStream,
    context: Context
): String? {
    var keyAlias: String? = null
    dir.listFiles().forEach { file ->
        if (file.name == METADATA_FILENAME) {
            keyAlias = context.contentResolver.openInputStream(file.uri)?.use{ inputStream ->
                inputStream.bufferedReader().use { it.readText() }
            }
        }
        val entryName = "$base${file.name}"
        val entry = TarArchiveEntry(entryName)

        if (file.isFile) {
            context.contentResolver.openInputStream(file.uri)?.use {
                entry.size = it.available().toLong()
                tarOut.putArchiveEntry(entry)
                it.copyTo(tarOut)
                tarOut.closeArchiveEntry()
            }
        } else {
            tarOut.putArchiveEntry(entry)
            tarOut.closeArchiveEntry()
            // Recursively add all other files
            addDirToTarAndGetKeyAlias(file, "$entryName/", tarOut, context)
        }
    }
    return keyAlias
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

