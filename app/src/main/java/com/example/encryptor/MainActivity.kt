package com.example.encryptor

import android.net.Uri
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import androidx.activity.result.contract.ActivityResultContracts
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.database.Cursor
import android.os.Bundle
import android.webkit.MimeTypeMap
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Button
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.example.encryptor.ui.theme.EncryptorTheme
import java.io.File

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        //enableEdgeToEdge()
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
