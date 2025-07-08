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
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream
import java.io.Closeable
import java.io.InputStream
import java.io.OutputStream

const val METADATA_FILENAME = ".encryptor"

data class IOStreams(
    val input: InputStream,
    val output: OutputStream
)

data class IOFileUris(
    val input: Uri?,
    val output: Uri?
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
fun <R> openIOStreamFromUris(
    inputOutputFileUris: IOFileUris,
    context: Context,
    block: (IOStreams) -> R   // Defines a lambda inside { IO -> R }.
): R? {
    val contentResolver = context.contentResolver
    val inputUri = inputOutputFileUris.input
    val outputUri = inputOutputFileUris.output

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

    var dummyInputFile: File? = null
    var dummyOutputFile: File? = null
    val dummyInputFileUri: Uri
    val dummyOutputFileUri: Uri

    val inputStream = if (inputUri != null) {
        openStream(inputUri, true)
    } else {
        dummyInputFile = File.createTempFile("inputDummy", ".tmp", context.cacheDir)
        dummyInputFileUri = Uri.fromFile(dummyInputFile)
        openStream(dummyInputFileUri, true)
    } as? InputStream

    val outputStream = if (outputUri != null) {
        openStream(outputUri, false)
    } else {
        dummyOutputFile = File.createTempFile("outputDummy", ".tmp", context.cacheDir)
        dummyOutputFileUri = Uri.fromFile(dummyOutputFile)
        openStream(dummyOutputFileUri, false)
    } as? OutputStream

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
    } finally {
        dummyInputFile?.delete()
        dummyOutputFile?.delete()
    }
}


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

// TODO: Disallow encrypting an already encrypted dir.
fun encryptButtonHandler(dirUri: Uri?, password: String, context: Context){
    dirUri ?: return

    val selectedRootDir = DocumentFile.fromTreeUri(context, dirUri)
    val metadataFile = selectedRootDir?.findFile(METADATA_FILENAME)
        ?: selectedRootDir?.createFile("application/octet-stream", METADATA_FILENAME)
    val metadataFileUri = metadataFile?.uri

    if (metadataFileUri == null) {
        Log.e("MetadataFile", "Failed to read or create \"${METADATA_FILENAME}\".")
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


fun getSelectedDirName(dirUri: Uri?, context: Context): String? {
    return dirUri?.let { uri ->
        return DocumentFile.fromTreeUri(context, uri)?.name ?: "Unknown"
    }
}


fun deleteAllFilesInDirUri(dirUri: Uri, context: Context, excludedFilenames: Set<String> = emptySet()) {
    val dir = DocumentFile.fromTreeUri(context, dirUri)
    dir?.listFiles()?.forEach { file ->
        if (file.name in excludedFilenames) {
            return@forEach
        }
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


fun createTarFile(dirUri: Uri, context: Context, excludedFilenames: Set<String> = emptySet()): File? {
    val rootDir = DocumentFile.fromTreeUri(context, dirUri) ?: return null
    val tarName = getSelectedDirName(dirUri, context)!! + ".tar"
    val tarFile = File(context.filesDir, tarName)

    TarArchiveOutputStream(FileOutputStream(tarFile)).use { tarOut ->
        addDirToTarArchive(rootDir, "", tarOut, context, excludedFilenames)
    }

    return tarFile
}


// FIXME: There are potential issues apparently. Ask chat.
// TODO: Refactor (too many args).
fun addDirToTarArchive(
    dirToAdd: DocumentFile,
    relativePathPrefix: String,
    tarOut: TarArchiveOutputStream,
    context: Context,
    excludedFilenames: Set<String> = emptySet()
) {
    dirToAdd.listFiles().forEach { dirEntry ->
        if (dirEntry.name in excludedFilenames) {
            return@forEach
        }

        val tarArchiveEntryName = "$relativePathPrefix${dirEntry.name}"
        val tarArchiveEntry = if (dirEntry.isDirectory) {
            TarArchiveEntry("$tarArchiveEntryName/")
        } else {
            TarArchiveEntry(tarArchiveEntryName)
        }

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


// TODO: Test extensively, can potentially mess up user data!
fun extractTarToDirectory(
    tarUri: Uri,
    targetDir: DocumentFile,
    context: Context
): Boolean {
    return try {
        context.contentResolver.openInputStream(tarUri)?.use { tarInputStream ->
            TarArchiveInputStream(tarInputStream).use { tarIn ->
                generateSequence { tarIn.nextEntry }.forEach { entry ->
                    val pathSegments = entry.name
                        .split('/')
                        .filter { it.isNotEmpty() }

                    // E.g., dirA/dirB/dirC.
                    if (entry.isDirectory) {
                        // Create the full path as folders.
                        createDocumentDirectoryHierarchy(targetDir, pathSegments)
                    } else {  // E.g., dirA/dirB/file.txt
                        // Only create parent folders.
                        val parentSegments = pathSegments.dropLast(1)
                        val fileName = pathSegments.last()

                        val parentDir = createDocumentDirectoryHierarchy(
                            targetDir,
                            parentSegments
                        )

                        // If the parentDir is not actually a directory, fail
                        if (!parentDir.isDirectory) {
                            Log.e("TAR-Extract", "Parent is not a directory: ${parentDir.name}")
                            error("Parent is not a directory")
                        }

                        // In case this file already exists (somehow), delete it to overwrite later.
                        parentDir.findFile(fileName)?.delete()

                        val newFile = parentDir.createFile(
                            "application/octet-stream",
                            fileName
                        ) ?: error("Failed to create file: $fileName")

                        context.contentResolver.openOutputStream(newFile.uri)?.use { out ->
                            tarIn.copyTo(out)
                        }
                    }
                }

            }
        }
        true
    } catch (e: Exception) {
        Log.e("TAR-Extract", "Error extracting TAR archive", e)
        false
    }
}


fun createDocumentDirectoryHierarchy(
    baseDir: DocumentFile,
    pathSegments: List<String>
): DocumentFile {
    var currentDir = baseDir

    for (segment in pathSegments) {
        if (segment.isBlank())
            continue

        val subDir = currentDir.findFile(segment)
        val subDirExists = subDir != null

        currentDir = if (subDirExists) {
            if (subDir!!.isDirectory) {
                subDir
            } else {
                Log.e("TAR-Extract", "Existing item is a file, not a directory: $segment")
                error("Path conflict: $segment is a file, but expected a directory")
            }
        } else {
            currentDir.createDirectory(segment) ?: error("Could not create directory $segment")
        }
    }

    return currentDir
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


@Preview(showBackground = true)
@Composable
fun GreetingPreview() {
    EncryptorTheme {
        Main()
    }
}
