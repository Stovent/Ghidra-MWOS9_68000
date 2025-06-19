/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Enum.java to edit this template
 */

package os9.module;

import java.io.IOException;

import ghidra.app.util.bin.ByteProvider;

/**
 *
 * @author Stovent
 */
public enum ModuleLang {
	Unspecified,
	Object,
	ICode,
	PCode,
	CCode,
	CobolCode,
	FortanCode,
	Reserved,
    UserDefined;

// 	public final byte value;

// 	private ModuleLang(byte value) {
// 		this.value = value;
// 	}

// 	public byte getValue() {
// 		return value;
// 	}

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

    public static ModuleLang fromRaw(byte raw) {
		return switch (raw) {
			case 0 -> Unspecified;
			case 1 -> Object;
			case 2 -> ICode;
			case 3 -> PCode;
			case 4 -> CCode;
			case 5 -> CobolCode;
			case 6 -> FortanCode;
			case 7 -> Reserved;
			case 8 -> Reserved;
			case 9 -> Reserved;
			case 10 -> Reserved;
			case 11 -> Reserved;
			case 12 -> Reserved;
			case 13 -> Reserved;
			case 14 -> Reserved;
			case 15 -> Reserved;
			default -> UserDefined;
		};
    }
}
