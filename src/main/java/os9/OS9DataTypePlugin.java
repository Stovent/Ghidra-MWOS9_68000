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

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import os9.cdi.CdfmDeviceDriverStaticStorage;
import os9.cdi.CdfmDriveTable;
import os9.cdi.CdfmPathDescriptor;
import os9.cdi.PlayControlBlock;
import os9.cdi.PlayControlList;
import os9.kernel.CommonDeviceStaticStorage;
import os9.kernel.DeviceTableEntry;
import os9.kernel.PathDescriptor;
import os9.kernel.ProcessDescriptor;
import os9.kernel.RegisterStack;
import os9.kernel.SystemGlobals;
import os9.module.DataHeader;
import os9.module.DeviceDriverHeader;
import os9.module.FileManagerHeader;
import os9.module.InitHeader;
import os9.module.ProgramHeader;
import os9.module.SystemHeader;
import os9.module.TrapHandlerHeader;

/**
 * Ghidra Plugin that registers OS-9 specific data types.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = "MWOS9_68000",
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "Loads Microware OS-9 data types in programs.",
	description = "Loads Microware OS-9 data types in programs."
)
//@formatter:on
public class OS9DataTypePlugin extends ProgramPlugin {

    public OS9DataTypePlugin(PluginTool tool) {
        super(tool);
    }

    @Override
    protected void programOpened(Program program) {
        Msg.info(this, "Program opened: " + program.getName());
		addOS9DataTypes(program.getDataTypeManager());
    }

	public static void addOS9DataTypes(DataTypeManager dtm) {
        int transaction = dtm.startTransaction("Adding OS-9 data types");

        addWithPointer(dtm, CdfmDeviceDriverStaticStorage.singleStaticDataType());
        addWithPointer(dtm, CdfmDriveTable.staticDataType());
        addWithPointer(dtm, CdfmPathDescriptor.staticDataType());
        addWithPointer(dtm, PlayControlBlock.staticDataType());
        addWithPointer(dtm, PlayControlList.staticDataType());

        addWithPointer(dtm, CommonDeviceStaticStorage.staticDataType());
        addWithPointer(dtm, DeviceTableEntry.staticDataType());
        addWithPointer(dtm, PathDescriptor.staticDataType());
        addWithPointer(dtm, ProcessDescriptor.staticDataType());
        addWithPointer(dtm, RegisterStack.staticDataType());
        addWithPointer(dtm, SystemGlobals.staticDataType());

        add(dtm, DataHeader.staticDataType());
        // add(dtm, DeviceDescriptorHeader.staticDataType());
        add(dtm, DeviceDriverHeader.staticDataType());
        add(dtm, FileManagerHeader.staticDataType());
        add(dtm, InitHeader.staticDataType());
        // add(dtm, ModuleHeader.staticDataType());
        add(dtm, ProgramHeader.staticDataType());
        add(dtm, SystemHeader.staticDataType());
        add(dtm, TrapHandlerHeader.staticDataType());

        dtm.endTransaction(transaction, true); // Commit changes.
    }

	public static void add(DataTypeManager dtm, DataType dt) {
        dtm.addDataType(dt, DataTypeConflictHandler.REPLACE_HANDLER);
    }

	public static void addWithPointer(DataTypeManager dtm, DataType dt) {
        dtm.addDataType(dt, DataTypeConflictHandler.REPLACE_HANDLER);
        dtm.addDataType(new Pointer32DataType(dt), DataTypeConflictHandler.REPLACE_HANDLER);
    }
}
