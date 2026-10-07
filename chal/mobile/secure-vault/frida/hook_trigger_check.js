Java.perform(function() {
    console.log("[*] Triggering integrity check via MethodChannel");
    
    // Hook the MethodChannel to intercept the check calls and return clean results
    var MethodChannel = Java.use("io.flutter.plugin.common.MethodChannel");
    var BinaryMessenger = Java.use("io.flutter.plugin.common.BinaryMessenger");
    
    // Override invokeMethod to return clean results for root checks
    MethodChannel.invokeMethod.overload('java.lang.String', 'java.lang.Object', 'io.flutter.plugin.common.MethodChannel$Result').implementation = function(method, args, result) {
        console.log("[*] MethodChannel.invokeMethod: " + method + " with args: " + args);
        
        if (method === "checkTestKeys" || method === "checkRootPackages" || 
            method === "checkSuBinary" || method === "checkEmulator" || 
            method === "checkDebuggableBuild") {
            console.log("[*] Root check called: " + method + " -> returning '0'");
            result.success("0");
            return;
        }
        
        // For other methods, call original
        return this.invokeMethod(method, args, result);
    };
    
    console.log("[*] MethodChannel hooked for root checks");
    
    // Now trigger the integrity check by calling the Flutter side
    // We need to send a message on the "securevault/rootcheck" channel
    var channel = MethodChannel.$new(
        Java.use("io.flutter.plugin.common.BinaryMessenger").getDefaultBinaryMessenger(),
        "securevault/rootcheck"
    );
    
    // Call the integrity check method
    console.log("[*] Calling checkIntegrity on Flutter side...");
    channel.invokeMethod("checkIntegrity", null, Java.use("io.flutter.plugin.common.MethodChannel$Result").$new({
        success: function(result) {
            console.log("[*] Integrity check result: " + result);
        },
        error: function(code, message, details) {
            console.log("[*] Integrity check error: " + code + " " + message);
        },
        notImplemented: function() {
            console.log("[*] Integrity check not implemented");
        }
    }));
    
    console.log("[*] Integrity check triggered");
});
