/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

package os9.module;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;
import os9.util.Helpers;
import os9.util.InvalidModuleHeaderException;
import os9.util.Structure;

/**
 *
 * @author Stovent
 */
public class ModuleHeader implements Structure {
    public static final String NAME = "Module Header";

    public static final int ID = 0x4AFC;
    public static final int SYSREV = 0x0001;

    public static final long NAME_OFFSET = 0x0C;
    public static final long TYPE_OFFSET = 0x12;
    public static final long LANG_OFFSET = 0x13;

    public final int m_id;
    public final int m_sysrev;
    // public final long m_size;
    // public final long m_owner;
    public long m_nameOffset;
    // public final int m_access;
    public final ModuleType m_type;
    public final ModuleLang m_lang;
    // public final int m_attributes;
    // public final int m_revision;
    // public final int m_editition;
    // public final long m_usage;
    // public final long m_symbol;
    public final int m_parity;

    public final Structure extraHeader;

    public final String moduleName;

    @Override
    public String getName() {
        return NAME;
    }

    public ModuleHeader(ByteProvider provider) throws InvalidModuleHeaderException, IOException {
		BinaryReader reader = new BinaryReader(provider, false); // Big-endian

        m_id = reader.readUnsignedShort(0);
        m_sysrev = reader.readUnsignedShort(2);
        if(m_id != ID) {
            throw new InvalidModuleHeaderException(String.format("Invalid module ID %04X, expected %04X", m_id, ID));
        }
        if(m_sysrev != SYSREV) {
            throw new InvalidModuleHeaderException(String.format("Invalid module SysRev 0x%04X, expected 0x%04X", m_sysrev, SYSREV));
        }

        m_parity = reader.readUnsignedShort(0x2E);
        int crc = computeHeaderParityCheck(provider);
        if(crc != m_parity) {
            throw new InvalidModuleHeaderException(String.format("Invalid computed header parity 0x%04X, expected 0x%04X", crc, m_parity));
        }

        // m_size = reader.readUnsignedInt(0x04);
        // m_owner = reader.readUnsignedInt(0x08);
        m_nameOffset = reader.readUnsignedInt(NAME_OFFSET);
        // m_access = reader.readUnsignedShort(0x10);
        m_type = ModuleType.fromRaw(reader.readUnsignedByte(TYPE_OFFSET));
        m_lang = ModuleLang.fromRaw((byte)reader.readUnsignedByte(LANG_OFFSET));
        // m_attributes = reader.readUnsignedByte(0x14);
        // m_revision = reader.readUnsignedByte(0x15);
        // m_editition = reader.readUnsignedShort(0x16);
        // m_usage = reader.readUnsignedInt(0x18);
        // m_symbol = reader.readUnsignedInt(0x1C);

        this.moduleName = reader.readAsciiString(m_nameOffset);

        if(m_type.equals(ModuleType.System) && this.moduleName.equalsIgnoreCase("init")) {
            this.extraHeader = new InitHeader(provider);
        } else {
            this.extraHeader = m_type.getExtraHeader(provider);
        }
    }

    public static int computeHeaderParityCheck(ByteProvider provider) throws IOException {
		BinaryReader reader = new BinaryReader(provider, false);

		int crc = 0xFFFF;

		for(int i = 0; i < 0x2E; i += 2) {
			crc ^= reader.readNextUnsignedShort();
		}

        return crc;
	}

    @Override
    public void applyToProgram(Address moduleAddress, Program program) throws CodeUnitInsertionException {
        Listing listing = program.getListing();

        Helpers.createString(program, moduleAddress, NAME_OFFSET, m_nameOffset);

        listing.setComment(moduleAddress.add(TYPE_OFFSET), CodeUnit.EOL_COMMENT, m_type.toString());
        listing.setComment(moduleAddress.add(LANG_OFFSET), CodeUnit.EOL_COMMENT, m_lang.toString());

        this.extraHeader.applyToProgram(moduleAddress, program);

        // TODO: add comment for enum types.
    }

    @Override
    public DataType toDataType() throws DuplicateNameException, IOException {
        StructureDataType struct = new StructureDataType(new CategoryPath("/OS-9"), NAME, 0);

        struct.add(new UnsignedShortDataType(), "M$ID", null);
        struct.add(new UnsignedShortDataType(), "M$SysRev", null);
        struct.add(new UnsignedIntegerDataType(), "M$Size", null);
        struct.add(new UnsignedIntegerDataType(), "M$Owner", null);
        struct.add(new UnsignedIntegerDataType(), "M$Name", null);
        struct.add(new UnsignedShortDataType(), "M$Accs", null);
        struct.add(new ByteDataType(), "M$Type", null);
        struct.add(new ByteDataType(), "M$Lang", null);
        struct.add(new ByteDataType(), "M$Attr", null);
        struct.add(new ByteDataType(), "M$Revs", null);
        struct.add(new UnsignedShortDataType(), "M$Edit", null);
        struct.add(new UnsignedIntegerDataType(), "M$Usage", null);
        struct.add(new UnsignedIntegerDataType(), "M$Symbol", null);
        struct.add(new ArrayDataType(StructConverter.BYTE, 0x0E, -1), "Reserved", null);
        struct.add(new UnsignedShortDataType(), "M$Parity", null);
        struct.add(this.extraHeader.toDataType(), this.extraHeader.getName(), null);

        return struct;
    }
}
