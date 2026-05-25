package com.bonded.bonded_app

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle

/**
 * Transparent activity for ADB-driven VPN control during debugging.
 * Runs entirely headless — it performs the requested action, logs the result,
 * and finishes immediately.  No UI is displayed.
 *
 * Usage:
 *   # Connect VPN (first paired server)
 *   adb shell am start -n com.bonded.bonded_app/.DebugVpnActivity \
 *       --es action connect
 *
 *   # Connect VPN (specific device)
 *   adb shell am start -n com.bonded.bonded_app/.DebugVpnActivity \
 *       --es action connect --es device_id "<uuid>"
 *
 *   # Disconnect VPN
 *   adb shell am start -n com.bonded.bonded_app/.DebugVpnActivity \
 *       --es action disconnect
 *
 *   # Print current session snapshot to logcat
 *   adb shell am start -n com.bonded.bonded_app/.DebugVpnActivity \
 *       --es action status
 *
 * All output is logged under the "DebugVPN" tag.
 */
class DebugVpnActivity : Activity() {

    companion object {
        private const val TAG = "DebugVPN"
        private const val REQUEST_VPN_PERMISSION = 1001
        private const val EXTRA_ACTION = "action"
        private const val EXTRA_DEVICE_ID = "device_id"
    }

    // Held across the permission grant round-trip.
    private var pendingDeviceId: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        handleIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleIntent(intent)
    }

    private fun handleIntent(intent: Intent?) {
        val action = intent?.getStringExtra(EXTRA_ACTION)?.lowercase()?.trim()
        log("Received action='$action'")

        when (action) {
            "connect" -> {
                val deviceId = intent.getStringExtra(EXTRA_DEVICE_ID)
                    ?: resolveFirstPairedDeviceId()

                if (deviceId == null) {
                    logError("No paired servers found — pair a server first")
                    finish()
                    return
                }

                pendingDeviceId = deviceId
                startVpnWithPermissionCheck(deviceId)
            }

            "disconnect" -> {
                log("Stopping VPN")
                BondedVpnService.stop(this)
                log("VPN stop requested")
                finish()
            }

            "status" -> {
                logStatus()
                finish()
            }

            null, "" -> {
                logError("No 'action' extra provided. Use --es action connect|disconnect|status")
                finish()
            }

            else -> {
                logError("Unknown action '$action'. Use connect, disconnect, or status")
                finish()
            }
        }
    }

    private fun startVpnWithPermissionCheck(deviceId: String) {
        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent == null) {
            // Permission already granted — start immediately.
            log("VPN permission already granted; starting VPN for device=$deviceId")
            BondedVpnService.start(this, deviceId, runInBackground = true)
            log("VPN start requested")
            finish()
        } else {
            // Need user to approve VPN permission (shows system dialog).
            log("Requesting VPN permission for device=$deviceId (system dialog will appear)")
            startActivityForResult(prepareIntent, REQUEST_VPN_PERMISSION)
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)

        if (requestCode != REQUEST_VPN_PERMISSION) {
            finish()
            return
        }

        val deviceId = pendingDeviceId
        pendingDeviceId = null

        if (resultCode == RESULT_OK && deviceId != null) {
            log("VPN permission granted; starting VPN for device=$deviceId")
            BondedVpnService.start(this, deviceId, runInBackground = true)
            log("VPN start requested")
        } else {
            logError("VPN permission denied or cancelled (resultCode=$resultCode)")
        }

        finish()
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private fun resolveFirstPairedDeviceId(): String? {
        val server = PairedServerStore.loadAll(this).firstOrNull()
        if (server != null) {
            log("Using first paired server: id=${server.id} addr=${server.publicAddress}")
        }
        return server?.id
    }

    private fun logStatus() {
        val running = BondedVpnService.isRunning()
        log("VPN running=$running")

        // Dump all paired servers so we can verify the stored public key.
        val servers = PairedServerStore.loadAll(this)
        if (servers.isEmpty()) {
            log("No paired servers stored")
        } else {
            servers.forEachIndexed { i, s ->
                log("Paired server[$i]: id=${s.id} addr=${s.publicAddress} key=${s.serverPublicKey.take(20)}…")
            }
        }

        val snapshot = BondedVpnService.getSessionSnapshot() ?: run {
            log("No session snapshot available")
            return
        }

        log(buildString {
            append("state=${snapshot["state"]}")
            append("  server=${snapshot["serverAddress"]}")
            append("  out=${snapshot["outboundPackets"]}/${snapshot["outboundBytes"]}B")
            append("  in=${snapshot["inboundPackets"]}/${snapshot["inboundBytes"]}B")
            val err = snapshot["lastError"]
            if (err != null) append("  lastError=$err")
        })
    }

    private fun log(msg: String) {
        android.util.Log.i(TAG, msg)
    }

    private fun logError(msg: String) {
        android.util.Log.e(TAG, msg)
    }
}
