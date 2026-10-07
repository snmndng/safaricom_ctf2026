Java.perform(function() {
    console.log("[*] Scheduling root checks on main thread");
    Java.scheduleOnMainThread(function() {
        console.log("[*] Running on main thread");
        var MainActivity = Java.use("com.example.securevault.MainActivity");
        var activityThread = Java.use("android.app.ActivityThread");
        var currentActivityThread = activityThread.currentActivityThread();
        var activities = currentActivityThread.getActivities();
        var iterator = activities.values().iterator();
        while (iterator.hasNext()) {
            var activityRecord = iterator.next();
            // Get the activity from the ActivityRecord
            var activityField = activityRecord.getClass().getDeclaredField("activity");
            activityField.setAccessible(true);
            var activity = activityField.get(activityRecord);
            if (activity && activity.getClass().getName().includes("MainActivity")) {
                console.log("[*] Found MainActivity: " + activity);
                try {
                    var result = activity.checkTestKeys();
                    console.log("[*] checkTestKeys: " + result);
                } catch (e) {
                    console.log("[*] Error: " + e);
                }
                try {
                    var result2 = activity.checkRootPackages();
                    console.log("[*] checkRootPackages: " + result2);
                } catch (e) {
                    console.log("[*] Error: " + e);
                }
                try {
                    var result3 = activity.checkSuBinary();
                    console.log("[*] checkSuBinary: " + result3);
                } catch (e) {
                    console.log("[*] Error: " + e);
                }
                try {
                    var result4 = activity.checkEmulator();
                    console.log("[*] checkEmulator: " + result4);
                } catch (e) {
                    console.log("[*] Error: " + e);
                }
                try {
                    var result5 = activity.checkDebuggableBuild();
                    console.log("[*] checkDebuggableBuild: " + result5);
                } catch (e) {
                    console.log("[*] Error: " + e);
                }
                break;
            }
        }
    });
});
