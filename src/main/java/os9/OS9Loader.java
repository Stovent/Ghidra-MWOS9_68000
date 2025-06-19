/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package os9;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.LockException;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.LanguageNotFoundException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
import os9.module.ModuleHeader;
import os9.util.InvalidModuleHeaderException;

/**
 * Loader for Microware OS-9 M68K modules.
 */
public class OS9Loader extends AbstractProgramWrapperLoader {
	public static final String LOADER_NAME = "Microware OS-9 68000 module";

	public static final String LANGUAGE_ID_STRING = "68000_OS9:BE:32:default";
	public static final LanguageID LANGUAGE_ID = new LanguageID(LANGUAGE_ID_STRING);

	public static final String MWOS9_COMPILER_ID_STRING = "MWOS9";
	public static final CompilerSpecID MWOS9_COMPILER_ID = new CompilerSpecID(MWOS9_COMPILER_ID_STRING);

	/**
	 * This is arbitrary, but it's best not to have 0x0000_0000 in the program space. That
	 * can confuse the Decompiler when it finds null pointer assignments. OS9 also puts some
	 * actually-used variables in code page 0, and we don't want to overlay them.
	 */
	public static final long DEFAULT_BASE_IMAGE_ADDRESS = 0x0000_1000;

	/**
	 * This is arbitrary. It should usually be higher than the base image address.
	 */
	public static final long DEFAULT_DATA_ADDRESS = 0x8000_0000;

	private static final String OPTION_NAME_IMAGE_BASE_ADDRESS = "Image Base Address";
	private static final String OPTION_NAME_DATA_ADDRESS = "Data Section Address";

// 	public OS9Loader() {
// 		Msg.showInfo(this, null, "OS9Loader", "OS9Loader");
// 	}

	@Override
	public String getName() {

		// Name the loader.  This name must match the name of the loader in the .opinion files.

		return LOADER_NAME;
	}

	/** Called when importorting a file to know if it can be used as the loader.
	 * @return The list of language/compiler pair the module is analysable with.
	 */
	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		BinaryReader reader = new BinaryReader(provider, false);

		short id = reader.readShort(0);
		short sysrev = reader.readShort(2); // Expect the sysrev field to be 1.
		boolean crcValid = verifyModuleCRC(provider);
		// Msg.showInfo(this, null, "findSupportedLoadSpecs", String.format("magic bytes: 0x%04X 0x%04X %b", id, sysrev, crcValid));
		if(id == 0x4AFC && sysrev == 1 && crcValid) {
			// loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair(LANGUAGE_ID, DEFAULT_COMPILER_ID), true));
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair(LANGUAGE_ID, MWOS9_COMPILER_ID), true));
		}

		return loadSpecs;
	}

	private boolean verifyModuleCRC(ByteProvider provider) {
		BinaryReader reader = new BinaryReader(provider, false);

		short crc = 0;

		for(int i = 0; i < 0x30; i += 2) {
			try {
				crc ^= reader.readNextShort();
			}
			catch(IOException e) {
				return false;
			}
		}
		// Msg.showInfo(this, null, "verifyModuleCRC", String.format("module CRC: 0x%04X", crc));

		return crc == (short)0xFFFF;
	}

	/** Called after clicking yes in the import file dialog to populate the program with the file bytes and data structures. */
	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException
	{
		// Msg.showInfo(this, null, "load", "");

		// CompilerSpec spec = program.getCompilerSpec();
		// for (PrototypeModel proto : spec.getCallingConventions()) {
		// 	Msg.showInfo(this, null, "load", proto.getName());
		// }

		for (Option option : options) {
			switch (option.getName()) {
			case OPTION_NAME_IMAGE_BASE_ADDRESS ->  {
				try {
					program.setImageBase((Address)option.getValue(), true);
				} catch (AddressOverflowException | LockException | IllegalStateException ex) {
					log.appendException(ex);
				}
			}
			// case OPTION_NAME_DATA_ADDRESS:
			// 	dataAddress = (Address) option.getValue();
			// 	break;
			}
		}

		Address baseAddress = program.getImageBase();
		FlatProgramAPI api = new FlatProgramAPI(program, monitor);
		byte[] bytes = provider.readBytes(0, provider.length());

		try {
			// Load the file bytes into the program.
			api.createMemoryBlock("Module", baseAddress, bytes, false);
		}
		catch(Exception e) {
			log.appendException(e);
		}

		// TODO: should I create more sections?

		applyToProgram(provider, program, log);
	}

	/** Populate the program with the header data structures. */
	private void applyToProgram(ByteProvider provider, Program program, MessageLog log) throws IOException {
		log.setStatus("Loading module header");

		ModuleHeader header;
		DataType headerDataType;
		try {
			header = new ModuleHeader(provider);
			headerDataType = header.toDataType();
		}
		catch(InvalidModuleHeaderException | DuplicateNameException e) {
			log.appendException(e);
			return;
		}

		Address imageBase = program.getImageBase();
		try {
			DataUtilities.createData(program, imageBase, headerDataType, -1, false, DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

			header.applyToProgram(imageBase, program);
		}
		catch(CodeUnitInsertionException e) {
			log.appendException(e);
		}
	}

	/** Possible options for the Import file dialog. */
	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list = super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		try {
			Language language = loadSpec.getLanguageCompilerSpec().getLanguage();
			var addressSpace = language.getAddressFactory().getDefaultAddressSpace();
			var baseAddress = addressSpace.getAddress(loadSpec.getDesiredImageBase());
			var dataAddress = addressSpace.getAddress(DEFAULT_DATA_ADDRESS);
			list.add(new Option(OPTION_NAME_IMAGE_BASE_ADDRESS, baseAddress));
			list.add(new Option(OPTION_NAME_DATA_ADDRESS, dataAddress));
		} catch (LanguageNotFoundException e) {
			e.printStackTrace();
			// If error, omit the options.
		}

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
		return super.validateOptions(provider, loadSpec, options, program);
	}
}
