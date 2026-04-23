plugins {
    id "com.android.application"
    id "org.jetbrains.kotlin.android"
    id "dev.flutter.flutter-gradle-plugin"
}

android {
    // Namespace harus persis sama dengan package di MainActivity.kt
    namespace "com.elvandito.vaultx"
    compileSdk 34

    defaultConfig {
        // ApplicationId adalah ID unik aplikasi Anda di sistem Android
        applicationId "com.elvandito.vaultx"
        minSdk 21
        targetSdk 34
        versionCode 1
        versionName "1.0.0"
    }

    buildTypes {
        release {
            // Menggunakan debug signing untuk kemudahan build di GitHub Actions tanpa keystore
            signingConfig signingConfigs.debug
            minifyEnabled false
            shrinkResources false
        }
    }

    compileOptions {
        sourceCompatibility JavaVersion.VERSION_17
        targetCompatibility JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = '17'
    }
}

flutter {
    // Menunjuk ke folder utama tempat pubspec.yaml berada
    source '../..'
}

dependencies {
    // Dependensi standar Android
    implementation "org.jetbrains.kotlin:kotlin-stdlib:1.8.22"
}
