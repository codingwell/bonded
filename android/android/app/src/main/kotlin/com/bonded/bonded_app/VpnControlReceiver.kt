package com.bonded.bonded_app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * Exported broadcast receiver for VPN control via adb (testing only).
 * Usage:
 *   adb shell am broadcast -a com.bonded.bonded_app.VPN_START com.bonded.bonded_app
 *   adb shell am broadcast -a com.bonded.bonded_app.VPN_STOP com.bonded.bonded_app
 */
class VpnControlReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        if (intent == null) return

        android.util.Log.i("VpnControlReceiver", "Received action: ${intent.action}")

        when (intent.action) {
            "com.bonded.bonded_app.VPN_START" -> {
                val deviceId = intent.getStringExtra("device_id")
                val runBackground = intent.getBooleanExtra("run_background", true)

                if (deviceId != null) {
                    // Explicit device ID provided
                    android.util.Log.i("VpnControlReceiver", "Starting VPN with device_id=$deviceId")
                    BondedVpnService.start(context, deviceId, runBackground)
                } else {
                    // Try to find first paired device
                    val firstPaired = PairedServerStore.loadAll(context).firstOrNull()
                    if (firstPaired != null) {
                        android.util.Log.i(
                            "VpnControlReceiver",
                            "Starting VPN with first paired device: ${firstPaired.id}",
                        )
                        BondedVpnService.start(context, firstPaired.id, runBackground)
                    } else {
                        android.util.Log.w("VpnControlReceiver", "No paired devices found")
                    }
                }
            }

            "com.bonded.bonded_app.VPN_STOP" -> {
                android.util.Log.i("VpnControlReceiver", "Stopping VPN")
                BondedVpnService.stop(context)
            }

            else -> {
                android.util.Log.w("VpnControlReceiver", "Unknown action: ${intent.action}")
            }
        }
    }
}
