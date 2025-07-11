package com.example.encryptor.util

import com.example.encryptor.crypto.models.BiometricMetadata
import com.example.encryptor.crypto.models.EncryptionHeader
import com.example.encryptor.crypto.models.HeaderField
import com.example.encryptor.crypto.models.MetadataField

const val BYTES_FOR_SIZE_FIELD_IN_HEADER = 2
val ENCRYPTION_HEADER_FIELDS = listOf(
    HeaderField(EncryptionHeader::contentCipherIv),
    HeaderField(EncryptionHeader::masterKeyPasswordCipherIv),
    HeaderField(EncryptionHeader::passwordSalt),
    HeaderField(EncryptionHeader::passwordEncryptedMasterKey)
)

const val METADATA_FILENAME = ".encryptor"
const val BYTES_FOR_SIZE_FIELD_IN_METADATA = 2
val BIOMETRIC_METADATA_FIELDS = listOf(
    MetadataField(BiometricMetadata::keyAliasStringBytes),
    MetadataField(BiometricMetadata::masterKeyBiometricCipherIv),
    MetadataField(BiometricMetadata::biometricallyEncryptedMasterKey),
)

val ENCRYPTOR_CHARSET = Charsets.UTF_8
