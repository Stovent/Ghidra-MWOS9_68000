/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

package os9.module;

import java.io.IOException;
import java.util.ArrayList;
import java.util.AbstractMap.SimpleEntry;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;
import os9.util.Helpers;
import os9.util.Structure;

/**
 * Init module extra fields. It is detected by name.
 * @author Stovent
 */
public class InitHeader implements Structure {
    public static final String NAME = "Init Header";

    public static final long SPARAM_OFFSET = 0x3C;
    public static final long SYSGO_OFFSET = 0x3E;
    public static final long SYSDEV_OFFSET = 0x40;
    public static final long CONSOL_OFFSET = 0x42;
    public static final long EXTENS_OFFSET = 0x44;
    public static final long CLOCK_OFFSET = 0x46;
    public static final long INSTALL_OFFSET = 0x50;
    public static final long OS9REV_OFFSET = 0x5A;
    public static final long MEMLIST_OFFSET = 0x6A;

    public final int m_sparam;
    public final int m_sysgo;
    public final int m_sysdev;
    public final int m_consol;
    public final int m_extens;
    public final int m_clock;
    public final int m_install;
    public final int m_os9rev;
    public final ArrayList<SimpleEntry<Long, ColoredMemoryStruct>> memoryList;

    public InitHeader(ByteProvider provider) throws IOException {
        BinaryReader reader = new BinaryReader(provider, false); // Big-endian

        m_sparam = reader.readUnsignedShort(SPARAM_OFFSET);
        m_sysgo = reader.readUnsignedShort(SYSGO_OFFSET);
        m_sysdev = reader.readUnsignedShort(SYSDEV_OFFSET);
        m_consol = reader.readUnsignedShort(CONSOL_OFFSET);
        m_extens = reader.readUnsignedShort(EXTENS_OFFSET);
        m_clock = reader.readUnsignedShort(CLOCK_OFFSET);
        m_install = reader.readUnsignedShort(INSTALL_OFFSET);
        m_os9rev = reader.readUnsignedShort(OS9REV_OFFSET);

        long memList = reader.readUnsignedShort(MEMLIST_OFFSET);
        memoryList = new ArrayList();
        if(memList > 0) {
            while(reader.readUnsignedInt(memList) != 0) {
                memoryList.add(new SimpleEntry(memList, new ColoredMemoryStruct(provider, memList)));
                memList += ColoredMemoryStruct.SIZEOF;
            }
        }
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public void applyToProgram(Address moduleAddress, Program program) throws CodeUnitInsertionException {
		Helpers.createString(program, moduleAddress, SPARAM_OFFSET, m_sparam);
		Helpers.createString(program, moduleAddress, SYSGO_OFFSET, m_sysgo);
		Helpers.createString(program, moduleAddress, SYSDEV_OFFSET, m_sysdev);
		Helpers.createString(program, moduleAddress, CONSOL_OFFSET, m_consol);
		Helpers.createString(program, moduleAddress, EXTENS_OFFSET, m_extens);
		Helpers.createString(program, moduleAddress, CLOCK_OFFSET, m_clock);
		Helpers.createString(program, moduleAddress, INSTALL_OFFSET, m_install);
		Helpers.createString(program, moduleAddress, OS9REV_OFFSET, m_os9rev);

        try {
            for(SimpleEntry<Long, ColoredMemoryStruct> memList : memoryList) {
                ColoredMemoryStruct cm = memList.getValue();
                // TODO: point only to the first one to avoid conflits?
                Helpers.createData(program, moduleAddress, MEMLIST_OFFSET, memList.getKey(), cm.toDataType());
                cm.applyToProgram(moduleAddress, program);
            }
        }
        catch(Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public DataType toDataType() throws DuplicateNameException, IOException {
        return staticDataType();
    }

    public static DataType staticDataType() throws DuplicateNameException, IOException {
        StructureDataType struct = new StructureDataType(new CategoryPath("/OS-9"), NAME, 0);

        struct.add(new UnsignedIntegerDataType(), "Reserved", null);
        struct.add(new UnsignedShortDataType(), "M$PollSz", null);
        struct.add(new UnsignedShortDataType(), "M$DevCnt", null);
        struct.add(new UnsignedShortDataType(), "M$Procs", null);
        struct.add(new UnsignedShortDataType(), "M$Paths", null);
        struct.add(new UnsignedShortDataType(), "M$SParam", null);
        struct.add(new UnsignedShortDataType(), "M$SysGo", null);
        struct.add(new UnsignedShortDataType(), "M$SysDev", null);
        struct.add(new UnsignedShortDataType(), "M$Consol", null);
        struct.add(new UnsignedShortDataType(), "M$Extens", null);
        struct.add(new UnsignedShortDataType(), "M$Clock", null);
        struct.add(new UnsignedShortDataType(), "M$Slice", null);
        struct.add(new UnsignedShortDataType(), "Reserved", null);
        struct.add(new UnsignedIntegerDataType(), "M$Site", null);
        struct.add(new UnsignedShortDataType(), "M$Instal", null);
        struct.add(new UnsignedIntegerDataType(), "M$CPUType", null);
        struct.add(new UnsignedIntegerDataType(), "M$OS9Lvl", null);
        struct.add(new UnsignedShortDataType(), "M$OS9Rev", null);
        struct.add(new UnsignedShortDataType(), "M$SysPri", null);
        struct.add(new UnsignedShortDataType(), "M$MinPty", null);
        struct.add(new UnsignedShortDataType(), "M$MaxAge", null);
        struct.add(new UnsignedIntegerDataType(), "Reserved", null);
        struct.add(new UnsignedShortDataType(), "M$Events", null);
        struct.add(new ByteDataType(), "M$Compat", null);
        struct.add(new ByteDataType(), "M$Compat2", null);
        struct.add(new UnsignedShortDataType(), "M$MemList", null);
        struct.add(new UnsignedShortDataType(), "M$IRQStk", null);
        struct.add(new UnsignedShortDataType(), "M$ColdTrys", null);

        return struct;
    }

    public class ColoredMemoryStruct implements Structure {
        public static final String NAME = "Colored Memory Struct";

        public static final long DESCRIPTION_OFFSET = 0x10;
        /** Length of the struct in bytes in emulated memory. */
        public static final long SIZEOF = 0x20;

        public final long descriptionStringOffset;
        /** Offset from the beginning of the module to the upper field. */
        public final long descriptionStringOffsetOffset;

        /** Creates a new ColoredMemoryStruct with the provider starting at the beginning of the module. */
        public ColoredMemoryStruct(ByteProvider provider, long structOffset) throws IOException {
            BinaryReader reader = new BinaryReader(provider, false); // Big-endian

            descriptionStringOffset = reader.readUnsignedShort(structOffset + DESCRIPTION_OFFSET);
            descriptionStringOffsetOffset = structOffset + DESCRIPTION_OFFSET;
        }

        @Override
        public String getName() {
            return NAME;
        }

        @Override
        public void applyToProgram(Address moduleAddress, Program program) throws CodeUnitInsertionException {
		    Helpers.createString(program, moduleAddress, descriptionStringOffsetOffset, descriptionStringOffset);
        }

        @Override
        public DataType toDataType() throws DuplicateNameException, IOException {
            return staticDataType();
        }

        public static DataType staticDataType() throws DuplicateNameException, IOException {
            StructureDataType struct = new StructureDataType(new CategoryPath("/OS-9"), NAME, 0);

            struct.add(new UnsignedShortDataType(), "Memory Type", null);
            struct.add(new UnsignedShortDataType(), "Priority", null);
            struct.add(new UnsignedShortDataType(), "Access permissions", null);
            struct.add(new UnsignedShortDataType(), "Search Block Size", null);
            struct.add(new UnsignedIntegerDataType(), "Low Memory Limit", null);
            struct.add(new UnsignedIntegerDataType(), "High Memory Limit", null);
            struct.add(new UnsignedShortDataType(), "Description String Offset", null);
            struct.add(new UnsignedShortDataType(), "Reserved", null);
            struct.add(new UnsignedIntegerDataType(), "Address Translation Adjustment", null);
            struct.add(new UnsignedIntegerDataType(), "Reserved", null);
            struct.add(new UnsignedIntegerDataType(), "Reserved", null);

            return struct;
        }
    }
}
