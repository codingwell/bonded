package com.bonded.bonded_app

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.time.Instant

data class PairedServerRecord(
    val id: String,
    val publicAddress: String,
    val serverPublicKey: String,
    val supportedProtocols: List<String>,
    val pairedAt: String,
)

object PairedServerStore {
    private const val PREFS_NAME = "bonded.paired_servers"
    private const val KEY_RECORDS = "records"
    private const val LEGACY_KEY_DEVICE_ID = "deviceId"
    private const val LEGACY_KEY_PUBLIC_ADDRESS = "publicAddress"
    private const val LEGACY_KEY_SERVER_PUBLIC_KEY = "serverPublicKey"
    private const val LEGACY_KEY_PAIRED_AT = "pairedAt"

    fun save(context: Context, record: PairedServerRecord) {
        val records = loadAll(context).filterNot { it.id == record.id }.toMutableList()
        records.add(record)
        persist(context, records)
    }

    fun loadAll(context: Context): List<PairedServerRecord> {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val raw = prefs.getString(KEY_RECORDS, "[]") ?: "[]"
        val parsed = parseRecords(raw)
        if (parsed.isNotEmpty()) {
            return parsed
        }

        // Backward-compatibility migration path for pre-array storage.
        val legacy = parseLegacySingleRecord(prefs)
        if (legacy != null) {
            persist(context, listOf(legacy))
            return listOf(legacy)
        }

        return emptyList()
    }

    fun findById(context: Context, id: String): PairedServerRecord? {
        return loadAll(context).firstOrNull { it.id == id }
    }

    fun delete(context: Context, id: String) {
        val records = loadAll(context).filterNot { it.id == id }
        persist(context, records)
    }

    private fun persist(context: Context, records: List<PairedServerRecord>) {
        val array = JSONArray()
        records.forEach { record ->
            array.put(
                JSONObject()
                    .put("id", record.id)
                    .put("publicAddress", record.publicAddress)
                    .put("serverPublicKey", record.serverPublicKey)
                    .put("supportedProtocols", JSONArray(record.supportedProtocols))
                    .put("pairedAt", record.pairedAt),
            )
        }

        context
            .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_RECORDS, array.toString())
            .apply()
    }

    private fun parseProtocols(array: JSONArray?): List<String> {
        if (array == null) {
            return emptyList()
        }

        return buildList {
            for (index in 0 until array.length()) {
                add(array.optString(index))
            }
        }
    }

    private fun parseRecords(raw: String): List<PairedServerRecord> {
        val array = try {
            JSONArray(raw)
        } catch (_: Exception) {
            return emptyList()
        }

        return buildList {
            for (index in 0 until array.length()) {
                val item = array.optJSONObject(index) ?: continue

                val id = item.optString("id").trim()
                val publicAddress = item.optString("publicAddress").trim()
                val serverPublicKey = item.optString("serverPublicKey").trim()
                if (id.isEmpty() || publicAddress.isEmpty() || serverPublicKey.isEmpty()) {
                    continue
                }

                add(
                    PairedServerRecord(
                        id = id,
                        publicAddress = publicAddress,
                        serverPublicKey = serverPublicKey,
                        supportedProtocols = parseProtocols(item.optJSONArray("supportedProtocols")),
                        pairedAt = item.optString("pairedAt", Instant.now().toString()),
                    ),
                )
            }
        }
    }

    private fun parseLegacySingleRecord(
        prefs: android.content.SharedPreferences
    ): PairedServerRecord? {
        val id = prefs.getString(LEGACY_KEY_DEVICE_ID, "")?.trim().orEmpty()
        val publicAddress = prefs.getString(LEGACY_KEY_PUBLIC_ADDRESS, "")?.trim().orEmpty()
        val serverPublicKey = prefs.getString(LEGACY_KEY_SERVER_PUBLIC_KEY, "")?.trim().orEmpty()
        if (id.isEmpty() || publicAddress.isEmpty() || serverPublicKey.isEmpty()) {
            return null
        }

        return PairedServerRecord(
            id = id,
            publicAddress = publicAddress,
            serverPublicKey = serverPublicKey,
            supportedProtocols = emptyList(),
            pairedAt = prefs.getString(LEGACY_KEY_PAIRED_AT, Instant.now().toString())
                ?: Instant.now().toString(),
        )
    }
}