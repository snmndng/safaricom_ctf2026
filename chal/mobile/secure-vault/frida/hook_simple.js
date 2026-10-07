Java.perform(function() {
    console.log("[*] Hooking MainActivity.checkTestKeys");
    var MainActivity = Java.use("com.example.securevault.MainActivity");
    MainActivity.checkTestKeys.implementation = function() {
        console.log("[*] checkTestKeys called - returning 0");
        return "0";
    };
    console.log("[*] Hook installed");
});
