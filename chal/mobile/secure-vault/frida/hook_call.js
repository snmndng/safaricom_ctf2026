Java.perform(function() {
    console.log("[*] Calling checkTestKeys directly");
    var MainActivity = Java.use("com.example.securevault.MainActivity");
    var instance = MainActivity.$new();
    var result = instance.checkTestKeys();
    console.log("[*] checkTestKeys result: " + result);
    
    console.log("[*] Calling checkRootPackages directly");
    var result2 = instance.checkRootPackages();
    console.log("[*] checkRootPackages result: " + result2);
    
    console.log("[*] Calling checkSuBinary directly");
    var result3 = instance.checkSuBinary();
    console.log("[*] checkSuBinary result: " + result3);
    
    console.log("[*] Calling checkEmulator directly");
    var result4 = instance.checkEmulator();
    console.log("[*] checkEmulator result: " + result4);
    
    console.log("[*] Calling checkDebuggableBuild directly");
    var result5 = instance.checkDebuggableBuild();
    console.log("[*] checkDebuggableBuild result: " + result5);
});
