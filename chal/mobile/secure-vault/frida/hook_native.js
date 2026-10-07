Java.perform(function() {
    console.log("[*] Hooking native _decryptFlag function");
    var libapp = Module.findBaseAddress("libapp.so");
    console.log("[*] libapp.so base address: " + libapp);
    
    // _decryptFlag is at offset 0x2134A8D0 from the string table
    // The actual function address is in the text section
    // Text section is at file offset 0x160000, vaddr 0x160000
    // So function vaddr = 0x160000 + (0x2134A8D0 - 0x160000) = 0x2134A8D0
    // But that's larger than the text section size (0x2333b0)
    // So the address in the string table is a Dart VM internal address
    
    // Let's search for the function in the text section
    var textSection = Module.findBaseAddress("libapp.so").add(0x160000);
    console.log("[*] Text section at: " + textSection);
    
    // Search for the string "_decryptFlag" in memory
    var decryptFlagPtr = Memory.scanSync(libapp, libapp.add(0x3a0000), "_decryptFlag");
    console.log("[*] _decryptFlag string locations: ", decryptFlagPtr);
    
    // Try to find the function by scanning for the string reference
    for (var i = 0; i < decryptFlagPtr.length; i++) {
        var addr = decryptFlagPtr[i].address;
        console.log("[*] Found _decryptFlag string at: " + addr);
        
        // Scan backwards for function prologue
        for (var offset = -100; offset <= 100; offset += 4) {
            var inst = addr.add(offset);
            var bytes = inst.readByteArray(4);
            if (bytes) {
                // Check for common ARM64 function prologue patterns
                var hex = bytes.toString('hex');
                console.log("  Offset " + offset + ": " + hex);
            }
        }
    }
});
