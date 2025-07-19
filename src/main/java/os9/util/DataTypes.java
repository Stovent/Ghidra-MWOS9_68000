/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

package os9.util;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.program.model.data.ArrayDataType;

/**
 *
 * @author Stovent
 */
public class DataTypes {
    public static final ByteDataType U8 = new ByteDataType();
    public static final UnsignedShortDataType U16 = new UnsignedShortDataType();
    public static final UnsignedIntegerDataType U32 = new UnsignedIntegerDataType();

    public static final Pointer32DataType VoidPointer = pointer(StructConverter.VOID);
    public static final Pointer32DataType U8Pointer = pointer(U8);
    public static final Pointer32DataType U16Pointer = pointer(U16);
    public static final Pointer32DataType U32Pointer = pointer(U32);

    public static Pointer32DataType pointer(DataType dt) {
        return new Pointer32DataType(dt);
    }

    public static ArrayDataType array(DataType dt, int nm) {
        return new ArrayDataType(dt, nm, -1);
    }

    public static ArrayDataType u8Array(int nm) {
        return new ArrayDataType(U8, nm, -1);
    }

    public static ArrayDataType u16Array(int nm) {
        return new ArrayDataType(U16, nm, -1);
    }

    public static ArrayDataType u32Array(int nm) {
        return new ArrayDataType(U32, nm, -1);
    }
}
