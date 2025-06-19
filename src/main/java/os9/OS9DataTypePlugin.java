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
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * Ghidra Plugin that registers OS-9 specific data types.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.UNSTABLE,
	packageName = "MWOS9_68000",
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "Loads Microware OS-9 data types in programs.",
	description = "Loads Microware OS-9 data types in programs."
)
//@formatter:on
public class OS9DataTypePlugin extends ProgramPlugin {

    public OS9DataTypePlugin(PluginTool tool) {
        super(tool);
        Msg.info(this, "OS-9 Data Type Plugin Loaded.");
    }

    @Override
    protected void programOpened(Program program) {
        Msg.info(this, "Program opened: " + program.getName());
		addOS9DataTypes(program.getDataTypeManager());
    }

	public static void addOS9DataTypes(DataTypeManager dtm) {
        for (DataType dt : OS9DataTypeRegistry.DATA_TYPES) {
            dtm.addDataType(dt, DataTypeConflictHandler.REPLACE_HANDLER);
        }
    }
}
