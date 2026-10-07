Java.perform(function() {
    console.log("[*] Setting up MethodChannel hook to trigger integrity check");
    
    var MethodChannel = Java.use("io.flutter.plugin.common.MethodChannel");
    var BinaryMessenger = Java.use("io.flutter.plugin.common.BinaryMessenger");
    
    // Hook the invokeMethod to return clean results for root checks
    MethodChannel.invokeMethod.overload('java.lang.String', 'java.lang.Object', 'io.flutter.plugin.common.MethodChannel$Result').implementation = function(method, args, result) {
        console.log("[*] MethodChannel.invokeMethod: " + method + " with args: " + args);
        
        if (method === "checkTestKeys" || method === "checkRootPackages" || 
            method === "checkSuBinary" || method === "checkEmulator" || 
            method === "checkDebuggableBuild") {
            console.log("[*] Root check method called: " + method + " -> returning '0'");
            result.success("0");
            return;
        }
        
        // For the actual integrity check trigger
        if (method === "checkIntegrity" || method === "runIntegrityCheck") {
            console.log("[*] Integrity check triggered via MethodChannel: " + method);
            result.success("0");
            return;
        }
        
        return this.invokeMethod(method, args, result);
    };
    
    // Also hook the MethodChannel constructor to capture the channel
    MethodChannel.$init.overload('io.flutter.plugin.common.BinaryMessenger', 'java.lang.String').implementation = function(messenger, name) {
        console.log("[*] MethodChannel created: " + name);
        if (name === "securevault/rootcheck") {
            console.log("[*] Found rootcheck channel!");
            this.$init(messenger, name);
            return;
        }
        return this.$init(messenger, name);
    };
    
    console.log("[*] MethodChannel hooks installed");
    
    // Now trigger the integrity check by calling the Flutter side
    Java.scheduleOnMainThread(function() {
        console.log("[*] Triggering integrity check on main thread...");
        try {
            var channel = MethodChannel.$new(
                BinaryMessenger.getDefaultBinaryMessenger(),
                "securevault/rootcheck"
            );
            
            console.log("[*] Calling checkIntegrity on Flutter side...");
            channel.invokeMethod("checkIntegrity", null, Java.use("io.flutter.plugin.common.MethodChannel$Result").$new({
                success: function(result) {
                    console.log("[*] Integrity check SUCCESS: " + result);
                },
                error: function(code, message, details) {
                    console.log("[*] Integrity check ERROR: " + code + " " + message);
                },
                notImplemented: function() {
                    console.log("[*] Integrity check NOT IMPLEMENTED");
                }
            }));
            
            // Also try runIntegrityCheck
            channel.invokeMethod("runIntegrityCheck", null, Java.use("io.flutter.plugin.common.MethodChannel$Result").$new({
                success: function(result) {
                    console.log("[*] runIntegrityCheck SUCCESS: " + result);
                },
                error: function(code, message, details) {
                    console.log("[*] runIntegrityCheck ERROR: " + code + " " + message);
                },
                notImplemented: function() {
                    console.log("[*] runIntegrityCheck NOT IMPLEMENTED");
                }
            }));
            
        } catch (e) {
            console.log("[*] Error triggering integrity check: " + e);
        }
    });
    
    console.log("[*] Integrity check trigger scheduled on main thread");
});
