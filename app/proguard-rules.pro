# NIVRA proguard rules. Release build has minification disabled by default
# (see app/build.gradle.kts) for prototype/demo simplicity; these rules are
# here for when minification is turned on for a production build.

-keep class com.nivra.agent.models.** { *; }
-keep class com.nivra.agent.storage.QueuedEventEntity { *; }
-keep class com.nivra.agent.storage.KnownPackageEntity { *; }
-keep class com.nivra.agent.storage.MetricsCounterEntity { *; }

-keepclassmembers class * extends androidx.room.RoomDatabase
-dontwarn org.jetbrains.annotations.**
