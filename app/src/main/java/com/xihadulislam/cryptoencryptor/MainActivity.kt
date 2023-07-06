package com.xihadulislam.cryptoencryptor

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.util.Log

class MainActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "MainActivity"
        private const val message = "hello how are you?" // your prompt message
        private const val password = "6lz4Ox#taw20X^HKe1QH" // your secret password (you can put any password here)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val enc = CryptoEncryptor.encrypt(password, message)

        Log.d(TAG, "onCreate: encrypt ->   $enc")

        enc?.let {
            val dec = CryptoEncryptor.decrypt(password, it)
            Log.d(TAG, "onCreate: decrypt ->   $dec")
        }

    }
}