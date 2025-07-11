package com.example.encryptor.crypto.serialisers

import android.util.Log
import com.example.encryptor.crypto.BlockIOUtils.readBinaryBlocksWithSizes
import com.example.encryptor.crypto.BlockIOUtils.writeBinaryBlocksWithSizes
import com.example.encryptor.crypto.EncryptionHeader
import com.example.encryptor.util.BYTES_FOR_SIZE_FIELD_IN_HEADER
import com.example.encryptor.util.ENCRYPTION_HEADER_FIELDS
import java.io.InputStream
import java.io.OutputStream

object HeaderSerialiser {
    fun writeEncryptionHeader(encryptionHeader: EncryptionHeader, outputStream: OutputStream): Boolean {
        return try {
            val blocks = ENCRYPTION_HEADER_FIELDS.map { it.property(encryptionHeader) }
            writeBinaryBlocksWithSizes(blocks, outputStream, BYTES_FOR_SIZE_FIELD_IN_HEADER)
            true
        } catch (e: Exception) {
            Log.e("WritingHeader", "Could not write the header.", e)
            false
        }
    }


    fun readEncryptionHeader(input: InputStream): EncryptionHeader? {
        return try {
            // Example result:
            // headerFieldValues = [
            //     contentCipherIv bytes,
            //     masterKeyPasswordCipherIv bytes,
            //     passwordSalt bytes,
            //     passwordEncryptedMasterKey bytes
            // ]
            val headerFieldValues = readBinaryBlocksWithSizes(
                input,
                ENCRYPTION_HEADER_FIELDS.size,
                BYTES_FOR_SIZE_FIELD_IN_HEADER
            )

            // Example result:
            // fieldMap = {
            //   EncryptionHeader::contentCipherIv → blocks[0],
            //   EncryptionHeader::masterKeyPasswordCipherIv → blocks[1],
            //   EncryptionHeader::passwordSalt → blocks[2],
            //   EncryptionHeader::passwordEncryptedMasterKey → blocks[3]
            // }
            val fieldMap = ENCRYPTION_HEADER_FIELDS
                .mapIndexed { index, field -> field.property to headerFieldValues[index] }
                .toMap()

            EncryptionHeader(
                contentCipherIv = fieldMap.getValue(EncryptionHeader::contentCipherIv),
                masterKeyPasswordCipherIv = fieldMap.getValue(EncryptionHeader::masterKeyPasswordCipherIv),
                passwordSalt = fieldMap.getValue(EncryptionHeader::passwordSalt),
                passwordEncryptedMasterKey = fieldMap.getValue(EncryptionHeader::passwordEncryptedMasterKey)
            )
        } catch (e: Exception) {
            Log.e("HeaderExtraction", "Failed to extract data from the header.", e)
            null
        }
    }
}
