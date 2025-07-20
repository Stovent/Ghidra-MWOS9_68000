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
public class PlayControlList implements StructConverter {
    public static final String NAME = "Play Control List";

    public PlayControlList() {
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

        struct.add(DataTypes.U8, "PCL_Ctrl", "Control byte");
        struct.add(DataTypes.U8, "reserved", null);
        struct.add(DataTypes.U8, "PCL_SMode", "Submode byte");
        struct.add(DataTypes.U8, "PCL_Type", "Coding Information byte");
        struct.add(DataTypes.U16, "PCL_Sig", "Signal to be sent on buffer full");
        struct.add(DataTypes.VoidPointer, "PCL_Nxt", "Pointer to next Play Control List"); // How to do recursively?
        struct.add(DataTypes.U8Pointer, "PCL_Buf", "Pointer to buffer");
        struct.add(DataTypes.U32, "PCL_BufSz", "Size of buffer");
        struct.add(DataTypes.U32, "PCL_Err", "Pointer to error buffer");
        struct.add(DataTypes.U16, "reserved", null);
        struct.add(DataTypes.U32, "PCL_Cnt", "Current offset");

        return struct;
    }
}
