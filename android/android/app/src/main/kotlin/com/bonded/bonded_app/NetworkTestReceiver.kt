package com.bonded.bonded_app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.InetAddress
import java.net.Socket
import java.net.URL
import kotlin.concurrent.thread

/**
 * Broadcast receiver for network diagnostic tests.
 * Usage:
 *   adb shell am broadcast -a com.bonded.bonded_app.TEST_DNS -e host charter.codingwell.net
 *   adb shell am broadcast -a com.bonded.bonded_app.TEST_TCP -e host charter.codingwell.net -e port 8080
 *   adb shell am broadcast -a com.bonded.bonded_app.TEST_HTTP -e url http://example.com
 */
class NetworkTestReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        if (intent == null) return

        android.util.Log.i("NetworkTest", "=== Test Action: ${intent.action} ===")

        when (intent.action) {
            "com.bonded.bonded_app.TEST_DNS" -> {
                val host = intent.getStringExtra("host") ?: "charter.codingwell.net"
                testDnsResolution(host)
            }

            "com.bonded.bonded_app.TEST_TCP" -> {
                val host = intent.getStringExtra("host") ?: "charter.codingwell.net"
                val port = intent.getIntExtra("port", 8080)
                testTcpConnection(host, port)
            }

            "com.bonded.bonded_app.TEST_HTTP" -> {
                val url = intent.getStringExtra("url") ?: "http://example.com"
                testHttpConnection(url)
            }

            "com.bonded.bonded_app.TEST_ALL" -> {
                testDnsResolution("charter.codingwell.net")
                testTcpConnection("charter.codingwell.net", 8080)
                testHttpConnection("http://example.com")
            }

            else -> {
                android.util.Log.w("NetworkTest", "Unknown action: ${intent.action}")
            }
        }

        android.util.Log.i("NetworkTest", "=== Test Complete ===\n")
    }

    private fun testDnsResolution(host: String) {
        android.util.Log.i("NetworkTest", ">>> DNS Resolution Test for: $host")
        thread {
            try {
                val startMs = System.currentTimeMillis()
                android.util.Log.d("NetworkTest", "Starting DNS lookup at ${System.currentTimeMillis()}")
                
                val addresses = InetAddress.getAllByName(host)
                val elapsedMs = System.currentTimeMillis() - startMs
                
                android.util.Log.i(
                    "NetworkTest",
                    "✓ DNS resolved '$host' to ${addresses.size} address(es) in ${elapsedMs}ms"
                )
                addresses.forEach { addr ->
                    android.util.Log.i(
                        "NetworkTest",
                        "  - ${addr.javaClass.simpleName}: ${addr.hostAddress}"
                    )
                }
            } catch (e: Exception) {
                android.util.Log.e(
                    "NetworkTest",
                    "✗ DNS resolution failed for '$host': ${e.message}",
                    e
                )
            }
        }
    }

    private fun testTcpConnection(host: String, port: Int) {
        android.util.Log.i("NetworkTest", ">>> TCP Connection Test to $host:$port")
        thread {
            var socket: Socket? = null
            try {
                val startMs = System.currentTimeMillis()
                android.util.Log.d("NetworkTest", "Starting TCP connection at ${System.currentTimeMillis()}")
                
                // Create socket with explicit timeout
                val socket = Socket()
                socket.connect(java.net.InetSocketAddress(host, port), 10000)  // 10s connect timeout
                
                val elapsedMs = System.currentTimeMillis() - startMs
                
                android.util.Log.i(
                    "NetworkTest",
                    "✓ TCP connection established to $host:$port in ${elapsedMs}ms"
                )
                android.util.Log.i(
                    "NetworkTest",
                    "  Local: ${socket.localAddress.hostAddress}:${socket.localPort}"
                )
                android.util.Log.i(
                    "NetworkTest",
                    "  Remote: ${socket.inetAddress.hostAddress}:${socket.port}"
                )
            } catch (e: Exception) {
                android.util.Log.e(
                    "NetworkTest",
                    "✗ TCP connection failed to $host:$port: ${e.message}",
                    e
                )
            } finally {
                try {
                    socket?.close()
                } catch (_: Exception) {
                }
            }
        }
    }

    private fun testHttpConnection(urlString: String) {
        android.util.Log.i("NetworkTest", ">>> HTTP Connection Test to $urlString")
        thread {
            try {
                val startMs = System.currentTimeMillis()
                android.util.Log.d("NetworkTest", "Starting HTTP request at ${System.currentTimeMillis()}")
                
                val url = URL(urlString)
                val connection = url.openConnection()
                connection.connectTimeout = 10000  // 10s timeout
                connection.readTimeout = 10000
                
                val elapsedMs = System.currentTimeMillis() - startMs
                
                android.util.Log.i(
                    "NetworkTest",
                    "✓ HTTP connection successful to $urlString in ${elapsedMs}ms"
                )
                
                if (connection is java.net.HttpURLConnection) {
                    val responseCode = connection.responseCode
                    val responseMessage = connection.responseMessage
                    android.util.Log.i(
                        "NetworkTest",
                        "  HTTP $responseCode: $responseMessage"
                    )
                }
            } catch (e: Exception) {
                android.util.Log.e(
                    "NetworkTest",
                    "✗ HTTP connection failed to $urlString: ${e.message}",
                    e
                )
            }
        }
    }
}
