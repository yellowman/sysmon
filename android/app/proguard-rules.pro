# Keep kotlinx.serialization classes
-keepclassmembers @kotlinx.serialization.Serializable class * {
    static **$* *;
}
-keepclassmembers class * {
    @kotlinx.serialization.SerialName <fields>;
}
-keepclasseswithmembers class * {
    @kotlinx.serialization.Serializable <init>(...);
}

# Firebase
-keep class com.google.firebase.** { *; }
-dontwarn com.google.firebase.**
