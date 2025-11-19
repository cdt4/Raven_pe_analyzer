"""
Disassembles x86/x64 code and detects function boundaries.
"""
import capstone
import pefile
from colorama import Fore, Style


class CodeDisassembler:
    """Handles code disassembly and basic analysis."""
    
    def __init__(self, pe):
        self.pe = pe
        # Set up the disassembler for the right architecture
        self.engine = capstone.Cs(
            capstone.CS_ARCH_X86,
            capstone.CS_MODE_32 if pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE else capstone.CS_MODE_64
        )
        self.engine.detail = True
        self.disasm_cache = {}
        self.api_calls = []
    
    def disassemble_section(self, section_name):
        """Disassemble a specific section's code."""
        # Check cache first
        if section_name in self.disasm_cache:
            return self.disasm_cache[section_name]
        
        instructions = []
        
        for section in self.pe.sections:
            if section.Name.decode().strip('\x00') == section_name:
                try:
                    code = section.get_data()
                    base_addr = self.pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
                    
                    for insn in self.engine.disasm(code, base_addr):
                        instructions.append(f"0x{insn.address:016X}: {insn.mnemonic} {insn.op_str}")
                        
                        # Track API calls
                        if insn.mnemonic in ['call', 'jmp']:
                            self._track_api_call(insn, instructions)
                    
                    # Cache it
                    self.disasm_cache[section_name] = instructions
                    return instructions
                    
                except Exception as e:
                    print(f"{Fore.YELLOW}Warning: Disassembly error in {section_name}: {e}{Style.RESET_ALL}")
        
        return []
    
    def _track_api_call(self, insn, output_list):
        """Try to identify which API is being called."""
        try:
            target = insn.op_str.strip()
            if target.startswith('0x'):
                target_addr = int(target, 16)
                
                # Check if it's an import
                if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
                    for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                        for imp in entry.imports:
                            if imp.address == target_addr:
                                api_name = imp.name.decode() if imp.name else f"ord_{imp.ordinal}"
                                output_list.append(f"        ; -> {entry.dll.decode()}!{api_name}")
                                self.api_calls.append({
                                    'address': insn.address,
                                    'target': target_addr,
                                    'dll': entry.dll.decode(),
                                    'api': api_name
                                })
                                return
        except:
            pass
    
    def find_functions(self):
        """Locate function boundaries in the code sections."""
        functions = []
        
        for section in self.pe.sections:
            section_name = section.Name.decode().strip('\x00')
            
            # Only look in code sections
            if not (section.Characteristics & 0x00000020):
                continue
            
            try:
                code = section.get_data()
                base_addr = self.pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
                
                current_func = None
                
                for insn in self.engine.disasm(code, base_addr):
                    # Function prologue patterns
                    is_prologue = (
                        (insn.mnemonic == 'push' and insn.op_str == 'ebp') or
                        (insn.mnemonic == 'mov' and insn.op_str == 'ebp, esp')
                    )
                    
                    if is_prologue:
                        # Save previous function if any
                        if current_func:
                            current_func['end'] = insn.address - 1
                            functions.append(current_func)
                        
                        # Start new function
                        current_func = {
                            'start': insn.address,
                            'end': 0,
                            'section': section_name,
                            'size': 0
                        }
                    
                    # Function epilogue (return)
                    elif insn.mnemonic == 'ret' and current_func:
                        current_func['end'] = insn.address
                        current_func['size'] = current_func['end'] - current_func['start']
                        functions.append(current_func)
                        current_func = None
                
                # Handle last function
                if current_func:
                    current_func['end'] = base_addr + len(code) - 1
                    current_func['size'] = current_func['end'] - current_func['start']
                    functions.append(current_func)
                    
            except Exception as e:
                print(f"{Fore.YELLOW}Warning: Function detection error in {section_name}: {e}{Style.RESET_ALL}")
        
        return functions
