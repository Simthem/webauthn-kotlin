# Debug builds are shrunk too, because an unminified Compose app is roughly 36 MB of dex
# and that is a miserable thing to sideload repeatedly. What is deliberately *not* done
# here is obfuscation and optimisation: names stay intact so stack traces and the debugger
# remain useful, and only unreachable code is dropped.
-dontobfuscate
-dontoptimize
-keepattributes SourceFile,LineNumberTable,*Annotation*
