/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

package os9.kernel;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

import os9.util.DataTypes;

/**
 * @author Stovent
 */
public class RegisterStack implements StructConverter {
    public static final String NAME = "Register Stack";

    public RegisterStack() {
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

        struct.add(DataTypes.u32Array(8), "D", null);
        struct.add(DataTypes.u32Array(8), "A", null);
        struct.add(DataTypes.U16, "SR", null);
        struct.add(DataTypes.U32, "PC", null);
        struct.add(DataTypes.U32, "SSP", null);
        struct.add(DataTypes.U32, "USP", null);
        struct.add(DataTypes.U32, "ISP", null);
        struct.add(DataTypes.U32, "MSP", null);
        struct.add(DataTypes.U32, "VBR", null);
        struct.add(DataTypes.U32, "CACR", null);
        struct.add(DataTypes.U32, "CAAR", null);
        struct.add(DataTypes.U32, "SFC", null);
        struct.add(DataTypes.U32, "DFC", null);
        struct.add(DataTypes.U16, "unused", null);

        return struct;
    }
}
