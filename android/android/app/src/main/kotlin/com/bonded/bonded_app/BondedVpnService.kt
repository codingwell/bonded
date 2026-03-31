package com.bonded.bonded_app

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor

class BondedVpnService : VpnService() {
    private var vpnInterface: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopSelf()
            return START_NOT_STICKY
        }

        if (vpnInterface == null) {
            vpnInterface = Builder()
                .setSession("Bonded")
                .setMtu(1500)
                .addAddress("10.8.0.2", 32)
                .addRoute("0.0.0.0", 0)
                .establish()
        }

        running = vpnInterface != null
        return START_STICKY
    }

    override fun onDestroy() {
        vpnInterface?.close()
        vpnInterface = null
        running = false
        super.onDestroy()
    }

    companion object {
        private const val ACTION_START = "com.bonded.bonded_app.vpn.START"
        private const val ACTION_STOP = "com.bonded.bonded_app.vpn.STOP"

        @Volatile
        private var running = false

        fun start(context: Context) {
            val intent = Intent(context, BondedVpnService::class.java).setAction(ACTION_START)
            context.startService(intent)
        }

        fun stop(context: Context) {
            val intent = Intent(context, BondedVpnService::class.java).setAction(ACTION_STOP)
            context.startService(intent)
        }

        fun isRunning(): Boolean = running
    }
}
