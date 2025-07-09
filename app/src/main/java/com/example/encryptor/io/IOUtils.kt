package com.example.encryptor.io

import android.content.Context
import android.net.Uri
import android.util.Log
import android.webkit.MimeTypeMap
import androidx.documentfile.provider.DocumentFile
import java.io.Closeable
import java.io.File
import java.io.InputStream
import java.io.OutputStream

data class IOStreams(
    val input: InputStream,
    val output: OutputStream
)

data class IOFileUris(
    val input: Uri?,
    val output: Uri?
)

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
