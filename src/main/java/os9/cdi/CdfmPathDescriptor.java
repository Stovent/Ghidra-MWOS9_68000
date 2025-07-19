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
import ghidra.util.InvalidNameException;

import os9.kernel.PathDescriptor;
import os9.util.DataTypes;

/**
 * @author Stovent
 */
public class CdfmPathDescriptor implements StructConverter {
    public static final String NAME = "CDFM Path Descriptor";

    public CdfmPathDescriptor() {
    }

    public static String getName() {
        return NAME;
    }

    @Override
    public DataType toDataType() throws DuplicateNameException, IOException {
        return staticDataType();
    }

    /** Returns a static data type that assumes there is a single drive. */
    public static StructureDataType staticDataType() {
        StructureDataType struct = PathDescriptor.commonStaticDataType();
        try {
            struct.setNameAndCategory(new CategoryPath("/CDI"), "CDFM Path Descriptor");
        }
        catch(DuplicateNameException | InvalidNameException e) {} // Should not happen.


        // File Manager Static Storage.
        struct.add(DataTypes.U16, "PD_Bln", "Number of characters in the File Manager buffer");
        struct.add(DataTypes.U32, "PD_Cp", "Current File position");
        struct.add(DataTypes.U32, "PD_FP", "Actual sector position of beginning of file");
        struct.add(DataTypes.U16, "PD_INTLV", "File interleave factor");
        struct.add(DataTypes.U32, "PD_Siz", "File size");
        struct.add(DataTypes.VoidPointer, "PD_FDAddr", "Byte address of file descriptor");
        struct.add(DataTypes.VoidPointer, "PD_NxtPD", "Next path descriptor in Play list"); // Need recursive data type.
        struct.add(DataTypes.VoidPointer, "PD_LstPD", "Last path descriptor in Play list"); // Need recursive data type.
        struct.add(DataTypes.U32, "PD_PSRT", "Starting sector of Play selection");
        struct.add(DataTypes.U16, "PD_PROCID", "Process ID of Owner of this path");
        struct.add(DataTypes.U32, "PD_PCBptr", "Pointer to Play Control Block or Status Block");
        struct.add(DataTypes.U16, "PD_DIRCT", "Direction of head movement");
        struct.add(DataTypes.pointer(PlayControlBlock.staticDataType()), "PD_PCB", "Reserved for CDFM use");
        struct.add(DataTypes.pointer(PlayControlList.staticDataType()), "PD_PCL", "Reserved for CDFM use");
        struct.add(DataTypes.U32Pointer, "PD_PCLArr", "Reserved for CDFM use");
        struct.add(DataTypes.pointer(CdfmDriveTable.staticDataType()), "PD_DTPtr", "Drive Table Pointer");
        struct.add(DataTypes.u8Array(6), "", null);
        struct.add(DataTypes.U8, "PD_FNum", "File number");
        struct.add(DataTypes.U8, "PD_CDFlags", "CDFM flag bits");

        struct.add(DataTypes.u8Array(23), "", null);

        // Options.
        struct.add(DataTypes.U8, "PD_DTP", "Device class");
        struct.add(DataTypes.U8, "PD_CDFC", "Function class");
        struct.add(DataTypes.U8, "PD_ErrSz", "Number of bytes per error bit");
        struct.add(DataTypes.U8, "PD_NDscs", "Number of discs in player");
        struct.add(DataTypes.U8, "PD_DNum", "Device number for Audio Processor or CD device");
        struct.add(DataTypes.U8, "PD_BFctr", "Blocking factor");
        struct.add(DataTypes.U32, "PD_Did", "Disc ID");
        struct.add(DataTypes.U16, "PD_Track", "Track type");
        struct.add(DataTypes.U16, "PD_XAR", "Extended attribute record size");
        struct.add(DataTypes.U32, "PD_CNUM", "Channel mask");
        struct.add(StructConverter.ASCII, "PD_TOK", "File name");
        struct.add(DataTypes.U16, "PD_PTNUM", "Path Table Entry Number");
        struct.add(DataTypes.U16, "PD_PTOFF", "Path Table Entry Offset");

        return struct;
    }
}
