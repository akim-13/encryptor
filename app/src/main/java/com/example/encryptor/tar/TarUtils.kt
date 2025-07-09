package com.example.encryptor.tar

import android.content.Context
import android.net.Uri
import android.util.Log
import androidx.documentfile.provider.DocumentFile
import com.example.encryptor.io.*
import org.apache.commons.compress.archivers.tar.TarArchiveEntry
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream
import java.io.File
import java.io.FileOutputStream

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
