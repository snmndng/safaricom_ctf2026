Java.perform(function() {
    console.log("[*] Getting MainActivity instance");
    var MainActivity = Java.use("com.example.securevault.MainActivity");
    var activityThread = Java.use("android.app.ActivityThread");
    var currentActivityThread = activityThread.currentActivityThread();
    var application = currentActivityThread.getApplication();
    console.log("[*] Application: " + application);
    
    // Get the MainActivity instance
    var activities = currentActivityThread.getActivities();
    var iterator = activities.values().iterator();
    while (iterator.hasNext()) {
        var activity = iterator.next();
        if (activity.getClass().getName().includes("MainActivity")) {
            console.log("[*] Found MainActivity instance: " + activity);
            var result = activity.checkTestKeys();
            console.log("[*] checkTestKeys result: " + result);
            
            var result2 = activity.checkRootPackages();
            console.log("[*] checkRootPackages result: " + result2);
            
            var result3 = activity.checkSuBinary();
            console.log("[*] checkSuBinary result: " + result3);
            
            var result4 = activity.checkEmulator();
            console.log("[*] checkEmulator result: " + result4);
            
            var result5 = activity.checkDebuggableBuild();
            console.log("[*] checkDebuggableBuild result: " + result5);
            break;
        }
    }
});
