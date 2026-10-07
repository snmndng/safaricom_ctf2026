Java.perform(function() {
    console.log("[*] Enumerating activities");
    var activityThread = Java.use("android.app.ActivityThread");
    var currentActivityThread = activityThread.currentActivityThread();
    
    // Use reflection to get the mActivities field
    var mActivities = currentActivityThread.getClass().getDeclaredField("mActivities");
    mActivities.setAccessible(true);
    var activitiesMap = mActivities.get(currentActivityThread);
    console.log("[*] Activities map: " + activitiesMap);
    
    var iterator = activitiesMap.values().iterator();
    while (iterator.hasNext()) {
        var activity = iterator.next();
        var className = activity.getClass().getName();
        console.log("[*] Activity: " + className);
        if (className.includes("MainActivity")) {
            console.log("[*] Found MainActivity!");
            try {
                var result = activity.checkTestKeys();
                console.log("[*] checkTestKeys: " + result);
            } catch (e) {
                console.log("[*] Error calling checkTestKeys: " + e);
            }
        }
    }
});
