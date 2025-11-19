"""
Parses the resource directory of PE files.
"""
import pefile
from colorama import Fore, Style


def parse_resources(pe):
    """Extract resource information from PE file."""
    resources = []
    
    if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        return resources
    
    try:
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            try:
                if resource_type.name is not None:
                    name = str(resource_type.name)
                else:
                    name = pefile.RESOURCE_TYPE.get(resource_type.struct.Id, resource_type.struct.Id)
                
                resource_entry = {
                    'type': name,
                    'id': resource_type.struct.Id,
                    'languages': []
                }
                
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                if hasattr(resource_lang, 'data'):
                                    lang_id = getattr(resource_lang.data.struct, 'Lang', 
                                                    getattr(resource_lang.data.struct, 'Language', None))
                                    if lang_id is not None:
                                        resource_entry['languages'].append(lang_id)
                
                resources.append(resource_entry)
            except Exception as e:
                print(f"{Fore.YELLOW}Warning: Error processing resource: {e}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.YELLOW}Warning: Error parsing resources: {e}{Style.RESET_ALL}")
    
    return resources
