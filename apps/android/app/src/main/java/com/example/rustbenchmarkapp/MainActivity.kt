package com.example.rustbenchmarkapp

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.example.rustbenchmarkapp.R
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import android.app.ActivityManager
import android.content.Context

class MainActivity : AppCompatActivity() {

  companion object {
      init {
          System.loadLibrary("rust_lib") // Replace with your library name
      }
  }

  // Native method declaration
  external fun runBenchmark(r1csPath: String, witnessPath: String): String

  private val MY_PERMISSIONS_REQUEST_READ_EXTERNAL_STORAGE = 1
  private lateinit var vcAndDiscloseButton: Button
  private lateinit var rsaButton: Button
  private lateinit var proveRsaButton: Button
  private lateinit var proveEcdsaButton: Button
  private lateinit var resultTextView: TextView

  override fun onCreate(savedInstanceState: Bundle?) {
      super.onCreate(savedInstanceState)

      val activityManager = getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
      val memoryClass = activityManager.memoryClass // Default heap size limit in MB
      val largeMemoryClass = activityManager.largeMemoryClass // Large heap size limit in MB if largeHeap is set

      println("Default memory limit: $memoryClass MB")
      println("Large memory limit (with largeHeap): $largeMemoryClass MB")

      // Set the UI layout
      setContentView(R.layout.activity_main)

      // Initialize UI components
      vcAndDiscloseButton = findViewById(R.id.vcAndDiscloseButton)
      rsaButton = findViewById(R.id.rsaButton)
      proveRsaButton = findViewById(R.id.proveRsaButton)
      proveEcdsaButton = findViewById(R.id.proveEcdsaButton)
      resultTextView = findViewById(R.id.resultTextView)

      setupButtons()
    }

  private fun setupButtons() {
      vcAndDiscloseButton.setOnClickListener {
          runBenchmarkInBackground("vc_and_disclose.r1cs", "vc_and_disclose.wtns")
      }
      rsaButton.setOnClickListener {
          runBenchmarkInBackground("rsa.r1cs", "rsa.wtns")
      }
      proveRsaButton.setOnClickListener {
          runBenchmarkInBackground("prove_rsa_65537_sha256.r1cs", "prove_rsa_65537_sha256.wtns")
      }
      proveEcdsaButton.setOnClickListener {
          runBenchmarkInBackground("prove_ecdsa_secp256r1_sha256.r1cs", "prove_ecdsa_secp256r1_sha256.wtns")
      }
  }

  private fun runBenchmarkInBackground(r1csFileName: String, witnessFileName: String) {
      Thread {
          val result = runBenchmarkFunction(r1csFileName, witnessFileName)
          // Update UI on the main thread
          runOnUiThread {
              resultTextView.text = result
          }
      }.start()
  }

  private fun runBenchmarkFunction(r1csFileName: String, witnessFileName: String): String {
      val r1csPath = "${filesDir.path}/$r1csFileName"
      val witnessPath = "${filesDir.path}/$witnessFileName"

      // Copy files from assets to internal storage
      copyAssetToFile(r1csFileName, r1csPath)
      copyAssetToFile(witnessFileName, witnessPath)

      // Call the native Rust function
      return runBenchmark(r1csPath, witnessPath)
  }

  private fun copyAssetToFile(assetName: String, filePath: String) {
      val file = File(filePath)
      if (file.exists()) {
          // File already exists, no need to copy
          return
      }
      try {
          assets.open(assetName).use { inputStream ->
              FileOutputStream(file).use { outputStream ->
                  inputStream.copyTo(outputStream)
              }
          }
      } catch (e: IOException) {
          e.printStackTrace()
          runOnUiThread {
              Toast.makeText(this, "Error copying asset $assetName", Toast.LENGTH_LONG).show()
          }
      }
  }

  override fun onRequestPermissionsResult(
      requestCode: Int,
      permissions: Array<String>,
      grantResults: IntArray
  ) {
      super.onRequestPermissionsResult(requestCode, permissions, grantResults)
      if (requestCode == MY_PERMISSIONS_REQUEST_READ_EXTERNAL_STORAGE) {
          if ((grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED)) {
              // Permission granted
              setupButtons()
          } else {
              // Permission denied, disable button and show message
              vcAndDiscloseButton.isEnabled = false
              rsaButton.isEnabled = false
              proveRsaButton.isEnabled = false
              proveEcdsaButton.isEnabled = false
              Toast.makeText(this, "Permission denied to read external storage", Toast.LENGTH_LONG).show()
          }
      }
  }
}