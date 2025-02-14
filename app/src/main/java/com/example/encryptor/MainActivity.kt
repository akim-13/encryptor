package com.example.encryptor

import android.net.Uri
import androidx.activity.result.contract.ActivityResultContracts
import android.content.Context
import android.database.Cursor
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
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
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.security.KeyStore
import java.security.KeyStoreException
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import org.apache.commons.compress.archivers.tar.TarArchiveEntry
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream
import java.io.FileInputStream
import java.io.RandomAccessFile
import java.util.UUID
import kotlin.experimental.xor

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
    ) { uri ->
        if (uri != null) {
            selectedUri.value = uri

            /*val tmpFile = File.createTempFile("test", ".enc")
            val tmpOut = File.createTempFile("testOut", ".txt")
            CryptoManager().encryptFile(uri, context, "test2", tmpFile)
            CryptoManager().decryptFile(tmpFile, "test2", tmpOut)
            println("TMPOUT CONTENTS ARE ${tmpOut.readText()}")*/
        }
    }

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
            Button(onClick = {encryptButton(selectedUri.value, context) }, modifier = Modifier.size(150.dp)) {
                Text("Encrypt")

            }
            Spacer(modifier = Modifier.width(40.dp))
            Button(onClick = { }, modifier = Modifier.size(150.dp)) {
                Text("Decrypt")
            }
        }
    }
}

fun getSelectedDirName(dirUri: Uri?, context: Context): String? {
    return dirUri?.let { uri ->
        return DocumentFile.fromTreeUri(context, uri)?.name ?: "Unknown"
    }
}

fun encryptButton(dirUri: Uri?, context: Context){
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
        // Notify the user that everything has been canceled, no operation performed.
    }

    context.filesDir.listFiles()?.forEach { file ->
        println("INTERNAL STORAGE CONTENT:${file.name}")
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

class CryptoManager {
    // Static properties, pertain to the class rather than its instances.
    companion object {
        private const val ALGORITHM = KeyProperties.KEY_ALGORITHM_AES
        private const val BLOCK_MODE = KeyProperties.BLOCK_MODE_GCM
        private const val PADDING = KeyProperties.ENCRYPTION_PADDING_NONE
        private const val TRANSFORMATION = "$ALGORITHM/$BLOCK_MODE/$PADDING"
    }

    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
    }

    private fun initCipher(mode: String, keyAlias: String, iv: ByteArray? = null): Cipher {
        val cipherInstance = Cipher.getInstance(TRANSFORMATION)

        return if (mode == "ENCRYPT") {
            cipherInstance.apply{ init(Cipher.ENCRYPT_MODE, retrieveOrCreateKey(keyAlias)) }
        } else if (mode == "DECRYPT" && iv != null) {
            cipherInstance.apply{ init(Cipher.DECRYPT_MODE, retrieveOrCreateKey(keyAlias), GCMParameterSpec(128, iv)) }
        } else {
            throw Exception("C'mon, just choose the right mode and iv if necessary")
        }
    }

    private fun retrieveOrCreateKey(keyAlias: String): SecretKey {
        try {
            val entry = keyStore.getEntry(keyAlias, null) as? KeyStore.SecretKeyEntry

            return if (entry != null) {
                entry.secretKey
            } else {
                createKey(keyAlias)
            }

        } catch (e: KeyStoreException) {
            // If the key is invalid (e.g., locked due to authentication), delete it.
            keyStore.deleteEntry(keyAlias)
            return createKey(keyAlias)
        } catch (e: Exception) {
            throw ErrorRetrievingKeyException("Error retrieving key: \"$keyAlias\"", e)
        }
    }

    private fun createKey(keyAlias: String): SecretKey {
        val keyGenerator = KeyGenerator.getInstance(ALGORITHM, "AndroidKeyStore")

        keyGenerator.init(
            KeyGenParameterSpec.Builder(
                keyAlias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(BLOCK_MODE)
                .setEncryptionPaddings(PADDING)
                .setUserAuthenticationRequired(false)
                .build()
        )

        return keyGenerator.generateKey()
    }

    fun encryptFile(uri: Uri, context: Context, keyAlias: String, outputFile: File): File {
        val contentResolver = context.contentResolver
        val fileInputStream = contentResolver.openInputStream(uri) ?: throw IOException("Failed to open input stream")
        val cipher = initCipher("ENCRYPT", keyAlias)

        outputFile.outputStream().use { unencryptedOutputStream ->
            unencryptedOutputStream.write(cipher.iv.size)
            unencryptedOutputStream.write(cipher.iv)
            CipherOutputStream(unencryptedOutputStream, cipher).use { encryptedOutputStream ->
                fileInputStream.use { input ->
                    // WARNING: Overflows if iv.size > 255. Modern iv size is up
                    // to 24 bytes, so might only become an issue in the future.
                    input.copyTo(encryptedOutputStream)
                }
            }
        }
        return outputFile
    }

    private fun extractIvFromInputStream(inputStream: FileInputStream): ByteArray {
        val ivSize = inputStream.read()
        val iv = ByteArray(ivSize)
        var totalRead = 0

        while (totalRead < ivSize) {
            val bytesRead = inputStream.read(iv, totalRead, ivSize - totalRead)
            if (bytesRead == -1) throw IOException("Unexpected EOF while reading IV")
            totalRead += bytesRead
        }

        return iv
    }

    fun decryptFile(encryptedFile: File, keyAlias: String, outputFile: File): File {
        encryptedFile.inputStream().use { encryptedInputStream ->
            val iv = extractIvFromInputStream(encryptedInputStream)
            val cipher = initCipher("DECRYPT", keyAlias, iv)

            CipherInputStream(encryptedInputStream, cipher).use { decryptedInputStream ->
                outputFile.outputStream().use { outputStream ->
                    decryptedInputStream.copyTo(outputStream)
                }
            }
        }
        return outputFile
    }

    fun isIntegrityCheckPassed(encryptedFile: File, keyAlias: String): Boolean {
        try {
            FileInputStream(encryptedFile).use { encryptedInputStream ->
                val iv = extractIvFromInputStream(encryptedInputStream)
                val cipher = initCipher("DECRYPT", keyAlias, iv)

                CipherInputStream(encryptedInputStream, cipher).use { decryptedInputStream ->
                    // Reduces the number of IO calls, making it faster.
                    val buffer = ByteArray(4096)
                    while (decryptedInputStream.read(buffer) != -1) {
                        // Just read through the file to force decryption/authentication
                    }
                }
            }
            return true
        } catch (e: Exception) {
            Log.e("IntegrityCheck", "ERROR: Unexpected failure during integrity verification")
            Log.e("IntegrityCheck", e.toString())
        }

        return false
    }

}

class ErrorRetrievingKeyException(message: String, cause: Throwable? = null) : Exception(message, cause)

class DebugOutputStream(private val wrapped: OutputStream) : OutputStream() {
    override fun write(b: Int) {
        Log.d("DEBUG", "Write 1 byte: $b") // Now logs correct values (0-255)
        wrapped.write(b)
    }
}

class DebugInputStream(private val wrapped: InputStream) : InputStream() {
    override fun read(): Int {
        val result = wrapped.read()
        Log.d("DEBUG", "Read 1 byte: $result") // Log in decimal
        return result
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        val result = wrapped.read(b, off, len)
        if (result > 0) {
            Log.d("DEBUG", "Read $result bytes: ${b.copyOfRange(off, off + result).joinToString(" ")}") // Decimal format
        }
        return result
    }

    override fun close() {
        Log.d("DEBUG", "Closing input stream")
        wrapped.close()
    }
}
