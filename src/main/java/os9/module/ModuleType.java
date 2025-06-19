/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Enum.java to edit this template
 */

package os9.module;

import java.io.IOException;

import ghidra.app.util.bin.ByteProvider;

import os9.util.Structure;

/**
 *
 * @author Stovent
 */
public enum ModuleType {
	Program(1),
	Subroutine(2),
	MultiModule(3),
	Data(4),
	CsdData(5),
	TrapLib(11),
	System(12),
	FileManager(13),
	DeviceDriver(14),
	DeviceDescriptor(15),
    Unknown(-1);

	public final int value;

	private ModuleType(int value) {
		this.value = value;
	}

	public int getValue() {
		return value;
	}

	// @Override
	// public String toString() {
	// 	return switch (this) {
	// 		case Program -> "Program";
	// 		case Subroutine -> "Subroutine";
	// 		case MultiModule -> "Multi-Module";
	// 		case Data -> "Data";
	// 		case CsdData -> "Configuration Status Descriptor";
	// 		case TrapLib -> "User Trap Library";
	// 		case System -> "System";
	// 		case FileManager -> "File Manager";
	// 		case DeviceDriver -> "Device Driver";
	// 		case DeviceDescriptor -> "Device Descriptor";
	// 		default -> "Unknown";
	// 	};
	// }

    public static ModuleType fromRaw(int raw) {
        for (ModuleType type : values()) {
            if (type.value == raw) {
                return type;
            }
        }
        return Unknown;
    }

	public Structure getExtraHeader(ByteProvider provider) throws IOException {
		return switch (this) {
			case Program -> new ProgramHeader(provider);
			case Data -> new DataHeader(provider);
			case TrapLib -> new TrapHandlerHeader(provider);
			case System -> new SystemHeader(provider);
			case FileManager -> new FileManagerHeader(provider);
			case DeviceDriver -> new DeviceDriverHeader(provider);
			case DeviceDescriptor -> new DeviceDescriptorHeader(provider);
			default -> new DataHeader(provider);
			// default -> null;
		};
	}
}
