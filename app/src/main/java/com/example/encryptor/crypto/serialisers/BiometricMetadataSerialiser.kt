package com.example.encryptor.crypto.serialisers

import android.util.Log
import com.example.encryptor.crypto.BiometricMetadata
import com.example.encryptor.crypto.BlockIOUtils.readBinaryBlocksWithSizes
import com.example.encryptor.crypto.BlockIOUtils.writeBinaryBlocksWithSizes
import com.example.encryptor.util.BIOMETRIC_METADATA_FIELDS
import com.example.encryptor.util.BYTES_FOR_SIZE_FIELD_IN_METADATA
import java.io.InputStream
import java.io.OutputStream

object BiometricMetadataSerialiser {
    fun writeBiometricMetadata(biometricMetadata: BiometricMetadata, outputStream: OutputStream): Boolean {
        return try {
            val blocks = BIOMETRIC_METADATA_FIELDS.map { it.property(biometricMetadata) }
            writeBinaryBlocksWithSizes(blocks, outputStream, BYTES_FOR_SIZE_FIELD_IN_METADATA)
            true
        } catch (e: Exception) {
            Log.e("WritingHeader", "Could not write the header.", e)
            false
        }
    }


    fun readBiometricMetadata(input: InputStream): BiometricMetadata? {
        return try {
            // Example result:
            // metadataFieldValues = [
            //     keyAliasStringBytes bytes,
            //     masterKeyBiometricCipherIv bytes,
            //     biometricallyEncryptedMasterKey bytes
            // ]
            val metadataFieldValues = readBinaryBlocksWithSizes(
                input,
                BIOMETRIC_METADATA_FIELDS.size,
                BYTES_FOR_SIZE_FIELD_IN_METADATA
            )

            // Example result:
            // fieldMap = {
            //   BiometricMetadata::keyAliasStringBytes → blocks[0],
            //   BiometricMetadata::masterKeyBiometricCipherIv → blocks[1],
            //   BiometricMetadata::biometricallyEncryptedMasterKey → blocks[2]
            // }
            val fieldMap = BIOMETRIC_METADATA_FIELDS
                .mapIndexed { index, field -> field.property to metadataFieldValues[index] }
                .toMap()

            BiometricMetadata(
                keyAliasStringBytes = fieldMap.getValue(BiometricMetadata::keyAliasStringBytes),
                masterKeyBiometricCipherIv = fieldMap.getValue(BiometricMetadata::masterKeyBiometricCipherIv),
                biometricallyEncryptedMasterKey = fieldMap.getValue(BiometricMetadata::biometricallyEncryptedMasterKey)
            )
        } catch (e: Exception) {
            Log.i("MetadataExtraction", "Metadata file is either empty or corrupted.", e)
            null
        }
    }
}
