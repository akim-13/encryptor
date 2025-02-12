package com.example.encryptor

import android.net.Uri
import androidx.activity.result.contract.ActivityResultContracts
import android.content.Context
import android.database.Cursor
import android.os.Build
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
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Button
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.example.encryptor.ui.theme.EncryptorTheme
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.UnrecoverableKeyException
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec

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
    val pickDocumentLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null) {
            val tmpFile = File.createTempFile("test", ".enc")
            val tmpOut = File.createTempFile("testOut", ".txt")
            CryptoManager().encryptFile(uri, context, "test2", tmpFile)
            CryptoManager().decryptFile(tmpFile, "test2", tmpOut)
            println("TMPOUT CONTENTS ARE ${tmpOut.readText()}")

            println("URI is $uri")
            val cursor = contentResolver.query(uri, null, null, null, null)
            displayQuery(cursor)
            val file = uri.toFile(context)
            if (file != null && file.exists()) {
                println("File successfully created at: ${file.absolutePath}")
                println("File size: ${file.length()} bytes")
            } else {
                println("File conversion failed!")
            }
            val content = file?.readBytes()
            println("First few bytes: ${content?.take(10)}")
        }
    }

    Column {
        Spacer(modifier = Modifier.height(20.dp))
        FilledTonalButton(
            onClick = {
                pickDocumentLauncher.launch(arrayOf("*/*"))
            },
            modifier = Modifier.height(40.dp)
        ) {
            Text("Pick a file")
        }

        Spacer(modifier = Modifier.height(40.dp))

        Row {
            Button(onClick = { }, modifier = Modifier.height(40.dp)) {
                Text("Encrypt")
            }
            Spacer(modifier = Modifier.width(40.dp))
            Button(onClick = { }, modifier = Modifier.height(40.dp)) {
                Text("Decrypt")
            }
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
            cipherInstance.apply{ init(Cipher.ENCRYPT_MODE, getKey(keyAlias)) }
        } else if (mode == "DECRYPT" && iv != null) {
            cipherInstance.apply{ init(Cipher.DECRYPT_MODE, getKey(keyAlias), GCMParameterSpec(128, iv)) }
        } else {
            throw Exception("C'mon, just choose the right mode and iv if necessary")
        }
    }

    private fun getKey(keyAlias: String): SecretKey {
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
        /* // That's for later to deal with SAF
        val cursor = contentResolver.query(uri, arrayOf(android.provider.MediaStore.MediaColumns.DISPLAY_NAME), null, null, null)
        val outputFilename = cursor?.use {
            if (it.moveToFirst()) {
                it.getString(0) + ".enc"
            } else {
                throw IOException("Failed to determine output file name because something is wrong with input file or access to it.")
            }
        }
        */
        val contentResolver = context.contentResolver
        val inputStream = contentResolver.openInputStream(uri) ?: throw IOException("Failed to open input stream")
        val cipher = initCipher("ENCRYPT", keyAlias)

        DebugOutputStream(outputFile.outputStream()).use { rawOutputStream ->
            rawOutputStream.write(cipher.iv.size)
            rawOutputStream.write(cipher.iv)
            CipherOutputStream(rawOutputStream, cipher).use { encryptedOutputStream ->
                inputStream.use { input ->
                    // WARNING: Overflows if iv.size > 255. Modern iv size is up
                    // to 24 bytes, so might only become an issue in the future.
                    input.copyTo(encryptedOutputStream)
                }
            }
        }
        return outputFile
    }

    fun decryptFile(encryptedFile: File, keyAlias: String, outputFile: File): File {
        val iv = ByteArray(12)
        DebugInputStream(encryptedFile.inputStream()).use { inputStream ->

            val ivSize = inputStream.read()
            var totalRead = 0

            while (totalRead < ivSize) {
                val bytesRead = inputStream.read(iv, totalRead, ivSize - totalRead)
                if (bytesRead == -1) throw IOException("Unexpected EOF while reading IV")
                totalRead += bytesRead
            }

            val cipher = initCipher("DECRYPT", keyAlias, iv)

            CipherInputStream(inputStream, cipher).use { encryptedInputStream ->
                outputFile.outputStream().use { outputStream ->
                    encryptedInputStream.copyTo(outputStream)
                }
            }
        }
        return outputFile
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
