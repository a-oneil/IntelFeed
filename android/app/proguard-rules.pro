# R8 rules for IntelFeed's release build.
#
# OkHttp, Retrofit, kotlinx.serialization, Coil, WorkManager, DataStore and Compose ship their own
# consumer rules, so they're not kept wholesale here: the old "-keep class okhttp3.** { *; }"-style
# rules (also for retrofit2, coil and jsoup) stopped R8 from shrinking any of them.

# Keep line numbers in crash stack traces; the source file name is hidden.
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile

# Generic signatures and annotations: Retrofit reads them from the API interface at runtime.
-keepattributes Signature, InnerClasses, EnclosingMethod, *Annotation*

# JSON models. kotlinx.serialization's own rules keep generated serializers; the models are kept
# whole as well because several are also decoded by hand (decodeFromJsonElement with .serializer()).
-keep class com.example.intelfeed.data.model.** { *; }

# Back-stack routes, saved with kotlinx.serialization when Android stops the process (RouteCodec).
-keep class com.example.intelfeed.ui.navigation.Route { *; }
-keep class com.example.intelfeed.ui.navigation.Route$* { *; }

# The Retrofit API interface (its methods are only called through Retrofit's proxy).
-keep interface com.example.intelfeed.data.network.IntelFeedApi { *; }

# WorkManager's Room database (WorkDatabase_Impl) is created by reflection. Without this, R8 removed
# its constructor and the release build crashed at startup (NoSuchMethodException, seen on the
# emulator with work-runtime 2.10.0).
-keep class * extends androidx.room.RoomDatabase { <init>(); }

# WorkManager creates the worker by reflection with this constructor.
-keep class com.example.intelfeed.notifications.IntelNotificationWorker {
    public <init>(android.content.Context, androidx.work.WorkerParameters);
}

# jsoup's optional dependency (re2j regex engine) isn't bundled.
-dontwarn com.google.re2j.**
-dontwarn org.jsoup.**
