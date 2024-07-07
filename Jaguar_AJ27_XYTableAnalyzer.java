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
package jaguar_aj27_xytable;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import java.util.TreeMap;

import java.util.function.BiConsumer;
import java.util.stream.Collectors;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This analyzer searches disassembled b68 Jaguar AJ27 files for data tables
 * 
 * The program listing is searched for the signatures
 * 		TBXK, LDX #dddd (37 9c 37 bc) or
 * 		TBYK, LDY #dddd (37 9d 37 bd)
 * 	if the instruction preceding TB_K is LDAB #0xf (f5 0f) then the signature is ignored
 * (since this will be accessing the sub-modules control area)
 * 
 * 	On any match, additional information is searched
 * 		a JSR within 6 instructions, logging the address of the function
 * 		a STD num,Z or STAA num,Z following the JSR (with possible intermediate instructions), logging the target address
 * 		a LDAA #0xdd prior to JSR, logging as possible row length
 * 		a LDD num,Z or LDE num,Z or LDAA num,Z prior to JSR, logging the source address(es)
 * 		the instruction prior to TB_K (e.g. TEKB (27 bb), LDAB #0xdd (f5 xx) ), logging the B value
 * 
 * 		Matches are grouped by common function, if one is found
 * 		For matches with no function, they are tagged with function 0xfffff
 * 
 * 		Matches are written to a file called inputfilename_XYTable.txt
 * 		in the users home directory
 * 			data output grouped by the function using the table
 * 
 * 		To store and sort this table data
 * 			inner class tableData is used to store the 'Data'
 * 			using an ArrayList tableList
 * 
 *  * 
 */
public class Jaguar_AJ27_XYTableAnalyzer extends AbstractAnalyzer {
	
	private BufferedWriter outFile;
	
	private byte[][] tableSig = {{0x37, (byte) 0x9c, 0x37, (byte) 0xbc}, {0x37, (byte) 0x9d, 0x37, (byte) 0xbd}};
	private byte[] ignoreSig = { (byte) 0xf5, 0x0f};
	
	class tableData{
		private int functionAddress;
		private Function function;
		private Address tableAddress;
		private Address tableEndAddress;
		private Address listingAddress;
		private int rowLength;
		private Data sourceVar1;
		private Data sourceVar2;
		private Data targetVar;
		private String comment;
		
		tableData(Function f, Address table, Address listing, int rowLen, Data s1, Data s2, Data t)
		{
			function = f;
			functionAddress = 0xffffff;
			if (function != null)		
				functionAddress = (int) f.getEntryPoint().getUnsignedOffset();
			tableAddress = table;
			listingAddress = listing;
			rowLength = rowLen;
			sourceVar1 = s1;
			sourceVar2 = s2;
			targetVar = t;
			comment = "";
			tableEndAddress = null; //placeholder, not implemented
		}
		
		static String getHeaderString()
		{
			return "Table Format: TableAddr, TableEndAddr, ListingAddr, RowLength,"
					+ "SourceVar1Addr, type (w:1, b:2), SourceVar2Addr, type, TargetAddr, type\n\n";
		}
		
		Integer getFunctionAddress()
		{
			return Integer.valueOf(functionAddress);
		}
		
		//basic serialization of tableEntry for output file
		int[] getTableDataAsInt()
		{
			int[] intData = new int[10];
			if (tableAddress != null)
			{
				intData[0] = (int) tableAddress.getUnsignedOffset();
			}
			
			//int[1] is tableEnd Address, default to 0 as not implemented
			
			intData[2] = (int) listingAddress.getUnsignedOffset();
			intData[3] = rowLength;
			
			//process sourceVar1
			if (sourceVar1 != null)
			{
				intData[4] = (int) sourceVar1.getAddress().getUnsignedOffset();
				intData[5] = 0;
				if (sourceVar1.getDataType().isEquivalent(WordDataType.dataType))
					intData[5] = 1;
				if (sourceVar1.getDataType().isEquivalent(ByteDataType.dataType))
					intData[5] = 2;
			}
			
			//process sourceVar2
			if (sourceVar2 != null)
			{
				intData[6] = (int) sourceVar2.getAddress().getUnsignedOffset();
				intData[7] = 0;
				if (sourceVar2.getDataType().isEquivalent(WordDataType.dataType))
					intData[7] = 1;
				if (sourceVar2.getDataType().isEquivalent(ByteDataType.dataType))
					intData[7] = 2;
			}
				
			//process targetVar
			if (targetVar != null)
			{
				intData[8] = (int) targetVar.getAddress().getUnsignedOffset();
				intData[9] = 0;
				if (targetVar.getDataType().isEquivalent(WordDataType.dataType))
					intData[9] = 1;
				if (targetVar.getDataType().isEquivalent(ByteDataType.dataType))
					intData[9] = 2;
			}

			return intData;
		}
		
		String getTableDataAsString()
		{
			String s = "{";
			int[] intData = this.getTableDataAsInt();
			for (int i : intData)
			{
				s = s.concat("0x"+Integer.toHexString(i)+", ");
			}
			//remove final comma and space
			s = s.substring(0, s.length() - 2);
			//add closing bracket
			s = s.concat("},\n");
			return s;
		}
		
		void setFunction(Function f)
		{
			function = f;
			functionAddress = 0xffffff;
			if (function != null)		
				functionAddress = (int) f.getEntryPoint().getUnsignedOffset();
		}
		
		void setTableAddress(Address a)
		{
			tableAddress = a;
		}
		
		void setSourceVar1(Data s1)
		{
			sourceVar1 = s1;
		}
		
		void setSourceVar2(Data s2)
		{
			sourceVar2 = s2;
		}

		void setTargetVar(Data t)
		{
			targetVar = t;
		}
		
		void setRowLength(int i)
		{
			rowLength = i;
		}

		void setComment(String s)
		{
			comment = s;
		}
		
		String getComment()
		{
			return comment;
		}
		
		Address getListingAddress()
		{
			return listingAddress;
		}
	}
	

	public Jaguar_AJ27_XYTableAnalyzer() {

		// TableXY analyzer
		// Searches disassembled b68 Jaguar AJ27 files for data tables
		// and stores results in output file

		super("XYTable", "Searches disassembled b68 Jaguar AJ27 files for data tables", AnalyzerType.BYTE_ANALYZER);
	}

	@Override
	public boolean getDefaultEnablement(Program program) {

		// not enabled by default

		return false;
	}

	@Override
	public boolean canAnalyze(Program program) {

		// return true if file executable format is "b68 Jaguar AJ27"
		Options options = program.getOptions(Program.PROGRAM_INFO);
		String format = options.getString("Executable Format", null);
		boolean result = (format.equals("b68 Jaguar AJ27")) ? true : false;
		return result;
	}

	@Override
	public void registerOptions(Options options, Program program) {

//		options.registerOption("Option name goes here", false, null,
//			"Option description goes here");
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		
		FlatProgramAPI fpapi = new FlatProgramAPI(program, monitor);

		//create the output file
		String outFileName = System.getProperty("user.home") + "/" +
				program.getName() + "_XYTable.txt";
		//storage for table data
		List<tableData> tData = new ArrayList<tableData>();
		//storage for formatted output data
		List<String> formattedOutput = new ArrayList<String>();
		formattedOutput.add(tableData.getHeaderString());
		
		BookmarkManager bookMgr = program.getBookmarkManager();
		
		monitor.setMessage("Searching for tables");
		
		try {
			outFile = new BufferedWriter(new FileWriter(outFileName));
		
			Listing code = program.getListing();
			//scan all instructions looking for tables, and log all found data
			InstructionIterator instructions = code.getInstructions(set, true);
			//move to second instruction, to prevent error when accessing getPrevious()
			instructions.next();
			while (instructions.hasNext()) {
				Instruction instr = instructions.next();
				if (isTableSignature(instr))
				{
					Address listing = instr.getDefaultFallThrough();
					
					// add Analysis bookmark with bookmark manager
					// Analysis [XYTable] : Found Table
					bookMgr.setBookmark(listing, "Analysis", "XYTable", "Found Table");
					
					// ?? add cross reference or pointer ??
					
					tableData t = new tableData(null, null, listing, 0, null, null, null);
					getTableAddress(instr, t, fpapi);
					getVars(instr, t, fpapi);
					
					tData.add(t);									
				}
			}
			
			//process all the table data
			
			//for each unique function, create a list of table entries using that function
			//noting that final entry (function 0xfffff) is all table entries that have no associated function
			
			Map<Integer, List<tableData>> funMap = tData.stream()
					.collect(Collectors.groupingBy(tableData::getFunctionAddress));
			
			//order from lowest to highest address of function		
			TreeMap<Integer, List<tableData>> orderedFunMap = new TreeMap<Integer, List<tableData>>(funMap);
			
			//create BiConsumer to process each TreeMap entry using forEach
			BiConsumer<Integer, List<tableData>> writeFileEntry = new BiConsumer<Integer, List<tableData>>()
			{
				public void accept(Integer i, List<tableData> l)
				{
					//write function address to formattedOutput
					formattedOutput.add("Function "+Integer.toHexString(i.intValue())+"\n{\n");
					//create ordered List of table entries
					//use comparator defined via lambda expression
					l.sort((t1, t2) -> {
						if (t1.getListingAddress().equals(t2.getListingAddress()))
						{
							return 0;
						}
						return ( t1.getListingAddress().subtract(t2.getListingAddress()) ) > 0 ? 1 : -1;
					});
					//write tableData integers to formatted Output
					l.forEach((t) -> {formattedOutput.add(t.getTableDataAsString());});
					//remove ending comma from last entry
					int elements = formattedOutput.size();
					String s = formattedOutput.get(elements-1);
					s = s.substring(0,s.length()-2);
					formattedOutput.remove(elements-1);
					formattedOutput.add(s);
					//write end characters
					formattedOutput.add("\n}\n");
				}
			};
			
			//write treemap orderedFunMap to formattedOUtput
			orderedFunMap.forEach(writeFileEntry);
			
			//output serialized integer data to log file
			//note can throw IOException
			for (String s : formattedOutput)
			{
				outFile.write(s);
			}
			
			outFile.close();
		}
		catch (IOException e) {
			monitor.setMessage("Issue writing to output file");
			String error = e.getMessage();
			if (error != null)
				monitor.setMessage(error);
			monitor.setMessage("Terminating analysis");
			return false;
		}
		
		return true;
	}
	
	private boolean isTableSignature(Instruction i)
	{
		boolean match = false;

		try
		{
			//get first instruction
			byte[] iBytes1 = i.getBytes();
			//check if two bytes long
			if (iBytes1.length == 2)
			{
				//get next instruction, unless at end of listing
				if (i.getNext() != null)
				{
					byte[] iBytes2 = i.getNext().getBytes();
					//check if 4 bytes long
					if (iBytes2.length == 4)
					{
						//copy first instruction into array of length 4
						byte[] sigCandidate = Arrays.copyOf(iBytes1, 4);
						//copy first 2 bytes of second instruction into this array
						System.arraycopy(iBytes2, 0, sigCandidate, 2, 2);
						for (byte[] testSig : tableSig)
						{
							match = match || (Arrays.equals(sigCandidate, testSig));
						}
						//check if previous instruction is not the ignore signature
						byte[] ignoreCandidate = i.getPrevious().getBytes();
						match = match && !(Arrays.equals(ignoreCandidate, ignoreSig));
					}
				}
			}
		}
		catch (MemoryAccessException e)
		{ /* pass */ }
			
		return match;
	}
	
	//method to compute Address of table
	private void getTableAddress(Instruction i, tableData t, FlatProgramAPI fpapi)
	{
		try
		{
			//get prefix value from register B setting
			int tableAddressOffset = 0xb0000;
			Instruction bSetting = i.getPrevious();
			if (bSetting.getMnemonicString().equals("TEKB"))
				tableAddressOffset = 0xb0000;
			if (bSetting.getMnemonicString().equals("LDAB"))
			{
				byte[] LDABbytes = bSetting.getBytes();
				if (LDABbytes[0] == (byte) 0xf5)
					tableAddressOffset = LDABbytes[1] << 16;
			}
			
			//get offset value from LDX/LDY
			Instruction loadOffset = i.getNext();
			
			int offset = (int) (loadOffset.getScalar(0).getUnsignedValue());
			
			tableAddressOffset += offset;
			Address tableAddress = fpapi.toAddr(tableAddressOffset);
			
			t.setTableAddress(tableAddress);
		}
		catch (MemoryAccessException e)
		{
			t.setComment("MemoryAccessException from getTableAddress()");
		}
		
	}
	
	//method to find source and target variables
	// uu unsigned, ssss signed
	//
	// For row count variables
	// LDAA immediate (75 uu), Scalar operand, defines a rowCount integer = dd
	// LDY immediate (37 bd dd uu), upper byte of dd uu defines a rowCount integer = dd
	//
	// For source variables
	// LDAA uu,Z (65 uu), Dynamic operand, defines a byte source with address 0xb0000 + 0xuu
	// LDAA ssss,Z (17 65 ss ss) defines a byte source with address 0xb0000 + ssss
	// LDD uu,Z (a5 uu) defines a word source variable with address 0xb0000 + 0xuu
	// LDD ssss,Z (37 e5 ss ss) defines a word source variable with address 0xb0000 + ssss
	// LDE ssss,Z (37 65 ss ss) defines a word source variable with address 0xb0000 + ssss
	//
	// for target variable (only searched if a function is found)
	// STAA uu,Z (6a uu)
	// STAA ssss,Z (17 6a ss ss)
	// STD uu,Z (aa,uu)
	// STD ssss,Z (37 ea ss ss)
	//
	// sometimes same result can be stored in multiple target variables
	// sometimes target is only after a branch or compare operation
	//
	//	if data for any element is not found, null is used
	//
	// sometimes there is a second call to function using same table, which this routine will not find
	
	private void getVars(Instruction i, tableData td, FlatProgramAPI fpapi)
	{
		try
		{
			Instruction instr = i.getNext(); //points at LDX/LDY
			int instrCount = 0;
			boolean funFound = false;
			boolean source1Found = false;
			
			do
			{
				instr = instr.getNext();
				instrCount++;
				byte[] instrBytes = instr.getBytes();
				
				//look for JSR to Function
				if (instr.getMnemonicString().equals("JSR"))
				{
					funFound = true;
					//should flow to function in disassembled listing
					//get this function, and add to tableData
					Address[] jsrAddress = instr.getFlows();
					if (jsrAddress != null)
					{
						Function f = fpapi.getFunctionAt(jsrAddress[0]);
						td.setFunction(f);
					}
				}
				
				// check for potential rowCount setting
				if (instrBytes.length == 2)
				{
					if (instrBytes[0] == (byte) 0x75) //LDAA #
						td.setRowLength(instrBytes[1] & 0xff);
				}
				if (instrBytes.length == 4)
				{
					if ((instrBytes[0] == (byte) 0x37) && (instrBytes[1] == (byte) 0xbd)) //LDY #
						td.setRowLength(instrBytes[2] & 0xff);
				}
				
				//check for source variable data
				Data sourceVar = findSourceVar(instrBytes, fpapi);
				if (sourceVar != null)
				{
					if (!source1Found)
					{
						td.setSourceVar1(sourceVar);
						source1Found = true;
					}
					else
					{
						td.setSourceVar2(sourceVar);
					}
				}
			}
			while ((instrCount < 6) && !funFound);
			
			//look for target variable
			if (funFound)
			{				
				Data targetVar = findTargetVar(instr, fpapi);
				if (targetVar != null)
				{
					td.setTargetVar(targetVar);
				}
			}
		}
		catch (Exception e)
		{
			td.setComment("Exception from getVars()");
		}
	}


	// For source variables
	// LDAA immediate (75 uu), Scalar operand, defines a rowCount integer = dd
	// LDAA uu,Z (65 uu), Dynamic operand, defines a byte source with address 0xb0000 + 0xuu
	// LDAA ssss,Z (17 65 ss ss) defines a byte source with address 0xb0000 + ssss
	// LDD uu,Z (a5 uu) defines a word source variable with address 0xb0000 + 0xuu
	// LDD ssss,Z (37 e5 ss ss) defines a word source variable with address 0xb0000 + ssss
	// LDE ssss,Z (37 65 ss ss) defines a word source variable with address 0xb0000 + ssss
	private Data findSourceVar(byte[] instrBytes, FlatProgramAPI fpapi) throws Exception
	{
		Data data = null;
		if (instrBytes.length == 2)
		{
			//check for byte source from LDAA
			if (instrBytes[0] == (byte) 0x65)
			{
				long offset = 0xb0000 + (instrBytes[1] & 0xff); //unsigned addition
				Address addr = fpapi.toAddr(offset);				
				data = getData(addr, ByteDataType.dataType, fpapi);
			}
			
			//check for word source from LDD
			if (instrBytes[0] == (byte) 0xa5)
			{
				long offset = 0xb0000 + (instrBytes[1] & 0xff); //unsigned addition
				Address addr = fpapi.toAddr(offset);				
				data = getData(addr, WordDataType.dataType, fpapi);
			}
		}
		
		if (instrBytes.length == 4)
		{
			//check for byte source from LDAA
			if ((instrBytes[0] == (byte) 0x17) && (instrBytes[1] == (byte) 0x65))
			{
				long offset = 0xb0000 + (instrBytes[2] << 8) + (instrBytes[3] & 0xff);
				Address addr = fpapi.toAddr(offset);				
				data = getData(addr, ByteDataType.dataType, fpapi);
			}
			
			//check for word source from LDD
			if ((instrBytes[0] == (byte) 0x37) && (instrBytes[1] == (byte) 0xe5))
			{
				long offset = 0xb0000 + (instrBytes[2] << 8) + (instrBytes[3] & 0xff);
				Address addr = fpapi.toAddr(offset);				
				data = getData(addr, WordDataType.dataType, fpapi);
			}
			
			//check for word source from LDE
			if ((instrBytes[0] == (byte) 0x37) && (instrBytes[1] == (byte) 0x65))
			{
				long offset = 0xb0000 + (instrBytes[2] << 8) + (instrBytes[3] & 0xff);
				Address addr = fpapi.toAddr(offset);				
				data = getData(addr, WordDataType.dataType, fpapi);
			}
		}
		
		return data;
	}

	// for target variable
	// STAA uu,Z (6a uu)
	// STAA ssss,Z (17 6a ss ss)
	// STD uu,Z (aa,uu)
	// STD ssss,Z (37 ea ss ss)
	//
	// follow default flow
	// 		if target variable, exit
	// 		if BRA (b0 dd), follow flow
	//		if CMPA BLS LDAA sequence, continue
	//		if BRSET or BRCLR or LDE or BCS, continue
	//		if TDE (27 7b) continue, look for sequence COMD STE 
	//		if any other instruction, exit
	//		if >4 instructions, exit
	
	private Data findTargetVar(Instruction instr, FlatProgramAPI fpapi) throws Exception
	{
		int instructionCount = 0;
		boolean keepSearching = true;
		Data data = null;

		do
		{
			instr = instr.getNext();
			instructionCount++;
			byte[] instrBytes = instr.getBytes();
			String instrMnemonic = instr.getMnemonicString();
			keepSearching = false; //default to exiting search
			
			//if BRA, move to branched instruction and continue search
			if (instrMnemonic.equals("BRA"))
			{
				Address[] flows = instr.getFlows();
				instr = fpapi.getInstructionAt(flows[0]);
				instructionCount++;
				instrBytes = instr.getBytes();
				instrMnemonic = instr.getMnemonicString();
			}

			if (instrBytes.length == 2)
			{
				//check for byte target STAA
				if (instrBytes[0] == (byte) 0x6a)
				{
					long offset = 0xb0000 + (instrBytes[1] & 0xff); //unsigned addition
					Address addr = fpapi.toAddr(offset);				
					data = getData(addr, ByteDataType.dataType, fpapi);
				}
				
				//check for word target STD
				if (instrBytes[0] == (byte) 0xaa)
				{
					long offset = 0xb0000 + (instrBytes[1] & 0xff); //unsigned addition
					Address addr = fpapi.toAddr(offset);				
					data = getData(addr, WordDataType.dataType, fpapi);
				}
			}
			
			if (instrBytes.length == 4)
			{
				//check for byte target STAA
				if ((instrBytes[0] == (byte) 0x17) && (instrBytes[1] == (byte) 0x6a))
				{
					long offset = 0xb0000 + (instrBytes[2] << 8) + (instrBytes[3] & 0xff);
					Address addr = fpapi.toAddr(offset);				
					data = getData(addr, ByteDataType.dataType, fpapi);
				}
				
				//check for word target STD
				if ((instrBytes[0] == (byte) 0x37) && (instrBytes[1] == (byte) 0xea))
				{
					long offset = 0xb0000 + (instrBytes[2] << 8) + (instrBytes[3] & 0xff);
					Address addr = fpapi.toAddr(offset);				
					data = getData(addr, WordDataType.dataType, fpapi);
				}
			}
			
			if ( instrMnemonic.equals("CMPA") || instrMnemonic.equals("BLS") || instrMnemonic.equals("LDAA")
					|| instrMnemonic.equals("BRCLR") || instrMnemonic.equals("BRSET") || instrMnemonic.equals("LDE")
					|| instrMnemonic.equals("BCS"))
			{
				keepSearching = true;
			}
			
			if (instrMnemonic.equals("TDE"))
			{
				instr = instr.getNext();
				instr = instr.getNext();
				instrBytes = instr.getBytes();
				//check for word target STE, in case sequence is TDE COMD STE
				if ((instrBytes[0] == (byte) 0x37) && (instrBytes[1] == (byte) 0x6a))
				{
					long offset = 0xb0000 + (instrBytes[2] << 8) + (instrBytes[3] & 0xff);
					Address addr = fpapi.toAddr(offset);				
					data = getData(addr, WordDataType.dataType, fpapi);
				}
			}
		}
		while ((instructionCount < 5) && keepSearching);
		
		return data;
	}
	
	private Data getData(Address a, DataType dt, FlatProgramAPI api) throws Exception
	{
		Data d = api.getDataAt(a);
		if (d == null)
		{
			d = api.createData(a, dt);
		}
		return d;
	}
}
