package com.example.encryptor.util

import com.example.encryptor.crypto.EncryptionHeader
// FIXME: Import this package.
import kotlin.reflect.full.memberProperties

const val METADATA_FILENAME = ".encryptor"

val ENCRYPTION_HEADER_FIELDS = EncryptionHeader::class
    .memberProperties
    .map { it.name }
