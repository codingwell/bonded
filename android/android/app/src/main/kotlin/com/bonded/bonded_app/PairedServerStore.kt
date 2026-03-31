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

    fun save(context: Context, record: PairedServerRecord) {
        val records = loadAll(context).filterNot { it.id == record.id }.toMutableList()
        records.add(record)
        persist(context, records)
    }

    fun loadAll(context: Context): List<PairedServerRecord> {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val raw = prefs.getString(KEY_RECORDS, "[]") ?: "[]"
        val array = JSONArray(raw)
        return buildList {
            for (index in 0 until array.length()) {
                val item = array.optJSONObject(index) ?: continue
                add(
                    PairedServerRecord(
                        id = item.optString("id"),
                        publicAddress = item.optString("publicAddress"),
                        serverPublicKey = item.optString("serverPublicKey"),
                        supportedProtocols = parseProtocols(item.optJSONArray("supportedProtocols")),
                        pairedAt = item.optString("pairedAt", Instant.now().toString()),
                    ),
                )
            }
        }
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
}