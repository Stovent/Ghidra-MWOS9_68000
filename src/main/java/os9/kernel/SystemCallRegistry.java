/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

package os9.kernel;

import java.util.Map;
import static java.util.Map.entry;

/**
 * Mapping of the system call ID to its information.
 * @author User
 */
public class SystemCallRegistry {
    public static final Map<Integer, SystemCallInfo> SYSCALLS = Map.ofEntries(
        entry(0x00, new SystemCallInfo("F$Link")),
        entry(0x01, new SystemCallInfo("F$Load")),
        entry(0x02, new SystemCallInfo("F$UnLink")),
        entry(0x03, new SystemCallInfo("F$Fork")),
        entry(0x04, new SystemCallInfo("F$Wait")),
        entry(0x05, new SystemCallInfo("F$Chain")),
        entry(0x06, new SystemCallInfo("F$Exit")),
        entry(0x07, new SystemCallInfo("F$Mem")),

        entry(0x08, new SystemCallInfo("F$Send")),
        entry(0x09, new SystemCallInfo("F$Icpt")),
        entry(0x0A, new SystemCallInfo("F$Sleep")),
        // entry(0x, new SystemCallInfo("F$")),

        entry(0x10, new SystemCallInfo("F$PrsNam")),
        
        entry(0x28, new SystemCallInfo("F$SRqMem")),
        entry(0x29, new SystemCallInfo("F$SRtMem")),
        entry(0x2A, new SystemCallInfo("F$IRQ")),
        entry(0x2B, new SystemCallInfo("F$IOQu")),

        entry(0x37, new SystemCallInfo("F$GProcP")),
        
        entry(0x60, new SystemCallInfo("F$Trans")),

        entry(0x80, new SystemCallInfo("I$Attach")),
        entry(0x81, new SystemCallInfo("I$Detach")),
        entry(0x82, new SystemCallInfo("I$Dup")),
        entry(0x83, new SystemCallInfo("I$Create")),
        entry(0x84, new SystemCallInfo("I$Open")),
        entry(0x85, new SystemCallInfo("I$MakDir")),
        entry(0x86, new SystemCallInfo("I$ChgDir")),
        entry(0x87, new SystemCallInfo("I$Delete")),

        entry(0x88, new SystemCallInfo("I$Seek")),
        entry(0x89, new SystemCallInfo("I$Read")),
        entry(0x8A, new SystemCallInfo("I$Write")),
        entry(0x8B, new SystemCallInfo("I$ReadLn")),
        entry(0x8C, new SystemCallInfo("I$WritLn")),
        entry(0x8D, new SystemCallInfo("I$GetStt")),
        entry(0x8E, new SystemCallInfo("I$SetStt")),
        entry(0x8F, new SystemCallInfo("I$Close")),

        entry(0x92, new SystemCallInfo("I$SGetSt"))
    );

    public static SystemCallInfo get(long index) {
        // Java doesn't allow indexing a Integer key with a long, need to cast.
        return SYSCALLS.get((int)index);
    }
}
