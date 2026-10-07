Java.perform(function() {
    console.log("[*] Hooking MethodChannel");
    var MethodChannel = Java.use("io.flutter.plugin.common.MethodChannel");
    
    // Hook the invokeMethod method
    MethodChannel.invokeMethod.overload('java.lang.String', 'java.lang.Object').implementation = function(method, args) {
        console.log("[*] MethodChannel.invokeMethod called: " + method + " with args: " + args);
        if (method.includes("check")) {
            console.log("[*] Root check method called: " + method);
            return "0"; // Return clean result
        }
        return this.invokeMethod(method, args);
    };
    
    console.log("[*] MethodChannel hooked");
});
