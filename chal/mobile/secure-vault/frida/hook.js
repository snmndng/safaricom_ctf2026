// Frida hook for SecureVault root checks and vault store
// Run with: frida -U -f com.example.securevault -l hook.js --no-pause

Java.perform(function() {
    console.log("[*] SecureVault Frida hook loaded");
    
    // Hook root checks in root_guard.dart
    // The checks are: checkRootPackages, checkTestKeys, checkSuBinary, 
    // checkEmulator, checkSuPaths, checkSystemRw, checkSuperuserApk
    
    // Try to hook Dart functions
    try {
        // Find the Dart VM
        var Dart = Module.findExportByName(null, "Dart_Initialize");
        if (Dart) {
            console.log("[*] Found Dart VM at: " + Dart);
        }
    } catch (e) {
        console.log("[!] Error finding Dart VM: " + e);
    }
    
    // Hook native bridge if it uses JNI
    var JNI_OnLoad = Module.findExportByName(null, "JNI_OnLoad");
    if (JNI_OnLoad) {
        console.log("[*] Found JNI_OnLoad at: " + JNI_OnLoad);
        Interceptor.attach(JNI_OnLoad, {
            onEnter: function(args) {
                console.log("[*] JNI_OnLoad called");
            },
            onLeave: function(retval) {
                console.log("[*] JNI_OnLoad returned: " + retval);
            }
        });
    }
    
    // Hook JNI functions
    var FindClass = Module.findExportByName("libart.so", "JNI_FindClass") || 
                    Module.findExportByName("libjvm.so", "JNI_FindClass");
    if (FindClass) {
        Interceptor.attach(FindClass, {
            onEnter: function(args) {
                var className = args[1].readUtf8String();
                if (className && (className.includes("securevault") || className.includes("root") || className.includes("vault"))) {
                    console.log("[*] FindClass: " + className);
                }
            }
        });
    }
});

// Hook Dart functions using Frida's Dart API
setTimeout(function() {
    if (typeof Dart !== "undefined") {
        console.log("[*] Dart API available");
        
        // Try to enumerate Dart classes
        Dart.enumerateClasses({
            onMatch: function(className) {
                if (className.includes("securevault") || className.includes("RootGuard") || className.includes("VaultStore")) {
                    console.log("[*] Found Dart class: " + className);
                }
            },
            onComplete: function() {
                console.log("[*] Dart class enumeration complete");
            }
        });
    } else {
        console.log("[!] Dart API not available, trying alternative approach");
    }
}, 1000);

// Alternative: Hook native functions in libapp.so
Interceptor.attach(Module.findExportByName("libapp.so", "_checkSystemRw@557231600"), {
    onEnter: function(args) {
        console.log("[*] _checkSystemRw called");
    },
    onLeave: function(retval) {
        console.log("[*] _checkSystemRw returned: " + retval);
        // Force return false (not compromised)
        retval.replace(0);
    }
}).catch(function(e) {
    console.log("[!] Could not hook _checkSystemRw: " + e);
});

// Hook checkRootPackages
Interceptor.attach(Module.findExportByName("libapp.so", "checkRootPackages"), {
    onEnter: function(args) {
        console.log("[*] checkRootPackages called");
    },
    onLeave: function(retval) {
        console.log("[*] checkRootPackages returned: " + retval);
        retval.replace(0);
    }
}).catch(function(e) {
    console.log("[!] Could not hook checkRootPackages: " + e);
});

// Hook checkSuBinary
Interceptor.attach(Module.findExportByName("libapp.so", "checkSuBinary"), {
    onEnter: function(args) {
        console.log("[*] checkSuBinary called");
    },
    onLeave: function(retval) {
        console.log("[*] checkSuBinary returned: " + retval);
        retval.replace(0);
    }
}).catch(function(e) {
    console.log("[!] Could not hook checkSuBinary: " + e);
});

// Hook checkTestKeys
Interceptor.attach(Module.findExportByName("libapp.so", "checkTestKeys"), {
    onEnter: function(args) {
        console.log("[*] checkTestKeys called");
    },
    onLeave: function(retval) {
        console.log("[*] checkTestKeys returned: " + retval);
        retval.replace(0);
    }
}).catch(function(e) {
    console.log("[!] Could not hook checkTestKeys: " + e);
});

// Hook checkEmulator
Interceptor.attach(Module.findExportByName("libapp.so", "checkEmulator@"), {
    onEnter: function(args) {
        console.log("[*] checkEmulator called");
    },
    onLeave: function(retval) {
        console.log("[*] checkEmulator returned: " + retval);
        retval.replace(0);
    }
}).catch(function(e) {
    console.log("[!] Could not hook checkEmulator: " + e);
});

// Hook checkSuPaths
Interceptor.attach(Module.findExportByName("libapp.so", "_checkSuPaths@557231600"), {
    onEnter: function(args) {
        console.log("[*] _checkSuPaths called");
    },
    onLeave: function(retval) {
        console.log("[*] _checkSuPaths returned: " + retval);
        retval.replace(0);
    }
}).catch(function(e) {
    console.log("[!] Could not hook _checkSuPaths: " + e);
});

// Hook checkSuperuserApk
Interceptor.attach(Module.findExportByName("libapp.so", "_checkSuperuserApk@557231600"), {
    onEnter: function(args) {
        console.log("[*] _checkSuperuserApk called");
    },
    onLeave: function(retval) {
        console.log("[*] _checkSuperuserApk returned: " + retval);
        retval.replace(0);
    }
}).catch(function(e) {
    console.log("[!] Could not hook _checkSuperuserApk: " + e);
});

// Hook _isRoot
Interceptor.attach(Module.findExportByName("libapp.so", "_isRoot@71420462"), {
    onEnter: function(args) {
        console.log("[*] _isRoot called");
    },
    onLeave: function(retval) {
        console.log("[*] _isRoot returned: " + retval);
        retval.replace(0);
    }
}).catch(function(e) {
    console.log("[!] Could not hook _isRoot: " + e);
});

// Hook vault store functions
Interceptor.attach(Module.findExportByName("libapp.so", "writeSecret"), {
    onEnter: function(args) {
        console.log("[*] writeSecret called");
        // Print arguments
        for (var i = 0; i < args.length; i++) {
            console.log("  arg[" + i + "]: " + args[i]);
        }
    },
    onLeave: function(retval) {
        console.log("[*] writeSecret returned: " + retval);
    }
}).catch(function(e) {
    console.log("[!] Could not hook writeSecret: " + e);
});

// Hook SQLite functions to see what's stored
var sqlite3_open = Module.findExportByName("libsqlite3.so", "sqlite3_open") ||
                   Module.findExportByName("libsqlite.so", "sqlite3_open");
if (sqlite3_open) {
    Interceptor.attach(sqlite3_open, {
        onEnter: function(args) {
            var dbPath = args[0].readUtf8String();
            console.log("[*] sqlite3_open: " + dbPath);
        }
    });
}

var sqlite3_exec = Module.findExportByName("libsqlite3.so", "sqlite3_exec") ||
                   Module.findExportByName("libsqlite.so", "sqlite3_exec");
if (sqlite3_exec) {
    Interceptor.attach(sqlite3_exec, {
        onEnter: function(args) {
            var sql = args[1].readUtf8String();
            if (sql.includes("vault") || sql.includes("secret") || sql.includes("INSERT") || sql.includes("SELECT")) {
                console.log("[*] sqlite3_exec: " + sql);
            }
        }
    });
}

console.log("[*] All hooks installed");