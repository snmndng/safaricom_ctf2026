Java.perform(function() {
    console.log("[*] Hooking root check methods to return '0'");
    
    var MainActivity = Java.use("com.example.securevault.MainActivity");
    
    MainActivity.checkTestKeys.implementation = function() {
        console.log("[*] checkTestKeys called -> returning '0'");
        return "0";
    };
    
    MainActivity.checkRootPackages.implementation = function() {
        console.log("[*] checkRootPackages called -> returning '0'");
        return "0";
    };
    
    MainActivity.checkSuBinary.implementation = function() {
        console.log("[*] checkSuBinary called -> returning '0'");
        return "0";
    };
    
    MainActivity.checkEmulator.implementation = function() {
        console.log("[*] checkEmulator called -> returning '0'");
        return "0";
    };
    
    MainActivity.checkDebuggableBuild.implementation = function() {
        console.log("[*] checkDebuggableBuild called -> returning '0'");
        return "0";
    };
    
    console.log("[*] All root check methods hooked to return '0'");
    
    // Now schedule the integrity check trigger on the main thread
    Java.scheduleOnMainThread(function() {
        console.log("[*] Running on main thread - triggering integrity check");
        try {
            var activityThread = Java.use("android.app.ActivityThread");
            var currentActivityThread = activityThread.currentActivityThread();
            var activities = currentActivityThread.getActivities();
            var iterator = activities.values().iterator();
            while (iterator.hasNext()) {
                var activityRecord = iterator.next();
                var activityField = activityRecord.getClass().getDeclaredField("activity");
                activityField.setAccessible(true);
                var activity = activityField.get(activityRecord);
                if (activity && activity.getClass().getName().includes("MainActivity")) {
                    console.log("[*] Found MainActivity, calling check methods...");
                    try {
                        var result = activity.checkTestKeys();
                        console.log("[*] checkTestKeys: " + result);
                    } catch (e) { console.log("[*] Error: " + e); }
                    try {
                        var result = activity.checkRootPackages();
                        console.log("[*] checkRootPackages: " + result);
                    } catch (e) { console.log("[*] Error: " + e); }
                    try {
                        var result = activity.checkSuBinary();
                        console.log("[*] checkSuBinary: " + result);
                    } catch (e) { console.log("[*] Error: " + e); }
                    try {
                        var result = activity.checkEmulator();
                        console.log("[*] checkEmulator: " + result);
                    } catch (e) { console.log("[*] Error: " + e); }
                    try {
                        var result = activity.checkDebuggableBuild();
                        console.log("[*] checkDebuggableBuild: " + result);
                    } catch (e) { console.log("[*] Error: " + e); }
                    break;
                }
            }
        } catch (e) {
            console.log("[*] Error on main thread: " + e);
        }
    });
});
