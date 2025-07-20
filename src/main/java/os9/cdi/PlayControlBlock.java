/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

package os9.cdi;

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
public class PlayControlBlock implements StructConverter {
    public static final String NAME = "Play Control Block";

    public PlayControlBlock() {
    }

    public static String getName() {
        return NAME;
    }

    @Override
    public DataType toDataType() throws DuplicateNameException, IOException {
        return staticDataType();
    }

    public static StructureDataType staticDataType() {
        StructureDataType struct = new StructureDataType(new CategoryPath("/CDI"), NAME, 0);

        struct.add(DataTypes.U16, "PCB_Stat", null);
        struct.add(DataTypes.U16, "PCB_Sig", null);
        struct.add(DataTypes.U32, "PCB_Rec", null);
        struct.add(DataTypes.U32, "PCB_Chan", null);
        struct.add(DataTypes.U16, "PCB_AChan", null);
        struct.add(DataTypes.U8Pointer, "PCB_Video", null);
        struct.add(DataTypes.U8Pointer, "PCB_Audio", null);
        struct.add(DataTypes.U8Pointer, "PCB_Data", null);

        return struct;
    }
}
