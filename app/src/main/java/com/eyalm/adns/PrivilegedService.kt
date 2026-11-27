package com.eyalm.adns

import androidx.annotation.Keep
import com.eyalm.adns.data.activation.PrivilegedGrantCommand
import java.io.File
import java.util.concurrent.TimeUnit

@Keep
class PrivilegedService : IPrivilegedService.Stub() {
    override fun grantWriteSecureSettings(packageName: String): Boolean {
        val pmBinary = File(PrivilegedGrantCommand.SYSTEM_PM_PATH)
            .takeIf { it.isFile && it.canExecute() }
            ?.absolutePath
            ?: "pm"

        val command = PrivilegedGrantCommand.buildPmGrantCommand(
            packageName = packageName,
            expectedApplicationId = BuildConfig.APPLICATION_ID,
            pmBinaryPath = pmBinary,
        )

        val proc = ProcessBuilder(command)
            .redirectErrorStream(true)
            .start()

        runCatching { proc.outputStream.close() }

        val output = StringBuilder()
        val readerThread = Thread {
            runCatching {
                proc.inputStream.bufferedReader().use { reader ->
                    val buffer = CharArray(1024)
                    var remaining = MAX_OUTPUT_CHARS
                    while (remaining > 0) {
                        val read = reader.read(buffer, 0, minOf(buffer.size, remaining))
                        if (read < 0) break
                        output.append(buffer, 0, read)
                        remaining -= read
                    }
                }
            }
        }.apply {
            isDaemon = true
            start()
        }

        val completed = proc.waitFor(GRANT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
        if (!completed) {
            proc.destroyForcibly()
            readerThread.join(500)
            throw RuntimeException("pm grant timed out")
        }

        readerThread.join(1_000)
        val code = proc.exitValue()
        if (code != 0) {
            throw RuntimeException("pm grant failed: exit=$code, output=$output")
        }
        return true
    }

    private companion object {
        const val GRANT_TIMEOUT_SECONDS = 10L
        const val MAX_OUTPUT_CHARS = 8 * 1024
    }
}