/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

package os9.kernel;

import java.io.IOException;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

import os9.util.DataTypes;

/**
 * @author Stovent
 */
public class CommonDeviceStaticStorage implements StructConverter {
    public static final String NAME = "Common Device Static Storage";

    public CommonDeviceStaticStorage(ByteProvider provider) throws IOException {
    }

    public static String getName() {
        return NAME;
    }

    @Override
    public DataType toDataType() throws DuplicateNameException, IOException {
        return staticDataType();
    }

    public static StructureDataType staticDataType() {
        StructureDataType struct = new StructureDataType(new CategoryPath("/OS-9"), NAME, 0);

        struct.add(DataTypes.U32, "V_PORT", "Device base port address");
        struct.add(DataTypes.U16, "V_LPRC", "Last active process ID");
        struct.add(DataTypes.U16, "V_BUSY", null);
        struct.add(DataTypes.U16, "V_WAKE", "Process ID to awaken");
        struct.add(DataTypes.U32, "V_PATHS", "singly-linked list of all paths currently open on this device");
        struct.add(DataTypes.u8Array(32), "", null);

        // TODO: add FM's static storage from the device driver module header M$Mem field?

        return struct;
    }
}
