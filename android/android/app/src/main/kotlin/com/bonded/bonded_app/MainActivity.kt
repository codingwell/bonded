package com.bonded.bonded_app

import android.net.VpnService
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

class MainActivity : FlutterActivity() {
	private val channelName = "bonded/native"

	companion object {
		private var nativeLoaded = false

		init {
			try {
				System.loadLibrary("bonded_ffi")
				nativeLoaded = true
			} catch (_: UnsatisfiedLinkError) {
				nativeLoaded = false
			}
		}
	}

	private external fun nativeApiVersion(): Int

	override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
		super.configureFlutterEngine(flutterEngine)

		MethodChannel(flutterEngine.dartExecutor.binaryMessenger, channelName)
			.setMethodCallHandler { call, result ->
				when (call.method) {
					"getNativeApiVersion" -> {
						if (!nativeLoaded) {
							result.success(-1)
							return@setMethodCallHandler
						}

						try {
							result.success(nativeApiVersion())
						} catch (_: UnsatisfiedLinkError) {
							result.success(-1)
						}
					}

					"getVpnStatus" -> {
						result.success(BondedVpnService.isRunning())
					}

					"startVpnService" -> {
						val prepareIntent = VpnService.prepare(this)
						if (prepareIntent != null) {
							result.success("permission_required")
						} else {
							BondedVpnService.start(this)
							result.success("started")
						}
					}

					"stopVpnService" -> {
						BondedVpnService.stop(this)
						result.success("stopped")
					}

					else -> result.notImplemented()
				}
			}
	}
}
