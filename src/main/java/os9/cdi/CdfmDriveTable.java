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
public class CdfmDriveTable implements StructConverter {
    public static final String NAME = "CDFM Drive Table";

    public CdfmDriveTable() throws IOException {
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

        struct.add(DataTypes.U32, "V_LastPos", "Last seek position");
        struct.add(DataTypes.U32, "V_PTSiz", "Path table size");
        struct.add(DataTypes.U32, "V_PTAdd", "Path table address");
        struct.add(DataTypes.U16, "V_CHILD", "Child process number");
        struct.add(DataTypes.U32, "V_PLAY", "Pointer to path descriptor of Play path");
        struct.add(DataTypes.U32, "V_DIRCT", "Direction of head movement");
        struct.add(DataTypes.U32, "V_DSize", "Size of CD-I disc");
        struct.add(DataTypes.U32, "V_ChanMask", "Channel mask");
        struct.add(DataTypes.U32, "V_APMask", "Audio channel mask");
        struct.add(DataTypes.U8, "V_PlayFlag", "Play in progress flag");
        struct.add(DataTypes.U8, "V_Paused", "Drive paused flag");
        struct.add(DataTypes.U8, "V_BFctr", "Blocking factor");
        struct.add(DataTypes.U8, "V_IRQlv", "Hardware interrupt level");
        struct.add(DataTypes.U8, "V_ROMFlag", "CDROM disc flag");
        struct.add(DataTypes.U8, "V_PTValid", "Path Table valid flag");
        struct.add(DataTypes.U32, "V_SoundMap", "Pointer to current playing soundmap descriptor by the CDFM device driver");
        struct.add(DataTypes.U16, "V_ASigPrc", "Process identifier for audio signal");
        struct.add(DataTypes.U8, "V_AudOff", "Flag for turning off audio");
        struct.add(DataTypes.U8, "V_AudPlay", "Flag for soundmap output");
        struct.add(DataTypes.U8, "V_ErFlags", "Error handling flags");
        struct.add(DataTypes.U8, "reserved", null);
        struct.add(DataTypes.U16, "V_SMPath", "Path on which current soundmap was started");
        struct.add(DataTypes.U32, "V_DirSect", "Directory sector buffer address");
        struct.add(DataTypes.U32, "V_DirSectNum", "Directory sector number");
        struct.add(DataTypes.u8Array(20), "reserved", null);

        return struct;
    }
}
