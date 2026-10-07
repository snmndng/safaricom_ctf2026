Java.perform(function() {
    console.log("[*] Hooking MainActivity root check methods");
    
    var MainActivity = Java.use("com.example.securevault.MainActivity");
    
    // Hook checkTestKeys
    MainActivity.checkTestKeys.implementation = function() {
        console.log("[*] checkTestKeys called");
        var result = this.checkTestKeys();
        console.log("[*] checkTestKeys returned: " + result);
        return "0"; // Return clean
    };
    
    // Hook checkRootPackages
    MainActivity.checkRootPackages.implementation = function() {
        console.log("[*] checkRootPackages called");
        var result = this.checkRootPackages();
        console.log("[*] checkRootPackages returned: " + result);
        return "0"; // Return clean
    };
    
    // Hook checkSuBinary
    MainActivity.checkSuBinary.implementation = function() {
        console.log("[*] checkSuBinary called");
        var result = this.checkSuBinary();
        console.log("[*] checkSuBinary returned: " + result);
        return "0"; // Return clean
    };
    
    // Hook checkEmulator
    MainActivity.checkEmulator.implementation = function() {
        console.log("[*] checkEmulator called");
        var result = this.checkEmulator();
        console.log("[*] checkEmulator returned: " + result);
        return "0"; // Return clean
    };
    
    // Hook checkDebuggableBuild
    MainActivity.checkDebuggableBuild.implementation = function() {
        console.log("[*] checkDebuggableBuild called");
        var result = this.checkDebuggableBuild();
        console.log("[*] checkDebuggableBuild returned: " + result);
        return "0"; // Return clean
    };
    
    // Hook signingCertSha256
    MainActivity.signingCertSha256.implementation = function() {
        console.log("[*] signingCertSha256 called");
        var result = this.signingCertSha256();
        console.log("[*] signingCertSha256 returned: " + result);
        return result; // Return original
    };
    
    console.log("[*] All MainActivity root check methods hooked");
});
