package com.example.encryptor.ui

import android.net.Uri
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
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
import com.example.encryptor.handlers.decryptButtonHandler
import com.example.encryptor.handlers.encryptButtonHandler
import com.example.encryptor.io.getSelectedDirName
import com.example.encryptor.ui.theme.EncryptorTheme

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


@Preview(showBackground = true)
@Composable
fun GreetingPreview() {
    EncryptorTheme {
        Main()
    }
}
