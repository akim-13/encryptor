package com.example.encryptor

import android.net.Uri
import androidx.activity.result.contract.ActivityResultContracts
import android.content.Context
import android.database.Cursor
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
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
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
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

// TODO: See if any of this works.
class cryptoManager {
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
        return if (mode == "ENCRYPT") {
            Cipher.getInstance(TRANSFORMATION).apply {
                init(Cipher.ENCRYPT_MODE, getKey(keyAlias))
            }
        } else if (mode == "DECRYPT" && iv != null) {
            Cipher.getInstance(TRANSFORMATION).apply {
                init(Cipher.DECRYPT_MODE, getKey(keyAlias), IvParameterSpec(iv))
            }
        } else {
            throw Exception("C'mon, just choose the right mode and iv if necessary.")
        }
    }

    private fun getKey(keyAlias: String): SecretKey? {
        try {
            val entry = keyStore.getEntry(keyAlias, null) as? KeyStore.SecretKeyEntry
            return entry?.secretKey ?: throw  ErrorRetrievingKeyException("Key not found: \"$keyAlias\"")
        } catch (e: Exception) {
            throw ErrorRetrievingKeyException("Error retrieving key: \"$keyAlias\"", e)
        }
    }


    private fun createKey(keyAlias: String): SecretKey {
        return KeyGenerator.getInstance(ALGORITHM).apply {
            init (
                KeyGenParameterSpec.Builder(
                    keyAlias,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setBlockModes(BLOCK_MODE)
                    .setUserAuthenticationRequired(true)
                    .setRandomizedEncryptionRequired(true)
                    .build()
            )
        }.generateKey()
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

        CipherOutputStream(outputFile.outputStream(), cipher).use { cipherOutputStream ->
            inputStream.use { input ->
                // WARNING: Overflows if iv.size > 255. Modern iv size is up
                // to 24 bytes, so might only become an issue in the future.
                cipherOutputStream.write(cipher.iv.size)
                cipherOutputStream.write(cipher.iv)
                input.copyTo(cipherOutputStream)
            }
        }

        return outputFile
    }

    fun decryptFile(encryptedFile: File, keyAlias: String, outputFile: File): File {
        encryptedFile.inputStream().use { inputStream ->

            val ivSize = inputStream.read()
            val iv = ByteArray(ivSize)
            // Read IV bytes and store them in iv
            // TODO: Doesn't guarantee all iv bytes are read. See chat's remarks.
            inputStream.read(iv)

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
