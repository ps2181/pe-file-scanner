import os
import csv
import pefile
import sys
import math
import hashlib
from cryptography import x509
from cryptography.hazmat.backends import default_backend

#folder_path=r"D:\test_exe_files"




def scan(file_path):


    pe = pefile.PE(file_path)
    path = os.path.abspath(os.path.dirname(__file__))

    csv_file_path = os.path.join(path, "output.csv")
    
    #print(path)
    key = ["cnt_dll", "cnt_nondll","str","entpy","no_DD","EX","init_data","uninit_data","dll_char","digi_sign","md5","arch","size_code","major_linker","minor_linker"]
    value = [0,0]

    pe = pefile.PE(file_path)

    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        import_table = pe.DIRECTORY_ENTRY_IMPORT
        
        for entry in import_table:
            imported_dll = entry.dll.decode()
            #print("Imported library:", imported_dll)

            if imported_dll.lower().endswith(".dll"):
                value[0] += 1
            else:
                value[1] += 1

    

    """importing the IAT address table and counting how many files have names or how many files are called by ordinals
    count=0
    ord_count=0
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            if imp.name:
                count += 1
            else:
                ord_count += 1

    value.append(count)
    value.append(ord)
"""
 

    "getting strings from the pefile structure"

    total_strings=0
    for section in pe.sections:
        section_data = section.get_data()
        section_strings = extract_strings(section_data)

        total_strings += len(section_strings)

    value.append(total_strings)

    "getting the section entropies of the file format"

    entropy = calculate_section_entropies(pe)
    value.append(entropy)

    "getting the total data directories"
    num_data_directories = data_directory(pe)
    value.append(num_data_directories)

    "getting the export table"
    num_exp_table = ex(pe)
    value.append(num_exp_table)

    "getting the initial data from the pefiles"
    initial_data = ini_data(pe)
    value.append(initial_data)

    "value of uninitialized data"
    uninitial_data = pe.OPTIONAL_HEADER.SizeOfUninitializedData
    value.append(uninitial_data)

    "getting the dll characteristics"
    dll_characteristics = get_dll_characteristics(pe)
    value.append(dll_characteristics)

    "checking if it has signature or not"
    digital_sign = has_digital_signature(pe)
    value.append(digital_sign)

    "getting the md5 hash"
    md5_hash = calculate_md5(file_path)
    value.append(md5_hash)

    "getting architecture"
    architecture = get_architecture(pe)
    value.append(architecture)

    "size of code"
    size_code = pe.OPTIONAL_HEADER.SizeOfCode
    value.append(size_code)

    "major linker"
    major_linker = pe.OPTIONAL_HEADER.MajorLinkerVersion
    value.append(major_linker)

    "minor linker"
    minor_linker = pe.OPTIONAL_HEADER.MinorLinkerVersion
    value.append(minor_linker)


    pe.close()
    check_csv_filepath(csv_file_path,key,value)

def check_csv_filepath(csv_file_path,key,value):

    # Check if CSV file is empty
        is_empty = not os.path.exists(csv_file_path) or os.stat(csv_file_path).st_size == 0

    # Write headers if the CSV file is empty
        if is_empty:
            with open(csv_file_path, "a", newline="") as csvfile:
                csv_writer = csv.writer(csvfile)
                csv_writer.writerow(key)

    # Append data to the CSV file
        with open(csv_file_path, "a", newline="") as csvfile:
            csv_writer = csv.writer(csvfile)
            csv_writer.writerow(value)


def extract_strings(data, min_length=4):
    strings = []
    current_string = ""

    for byte in data:
        if 0x20 <= byte <= 0x7E:  # Printable ASCII characters
            current_string += chr(byte)
        else:
            if len(current_string) >= min_length:
                strings.append(current_string)
            current_string = ""

    return strings

def calculate_entropy(data):
    entropy = 0
    total_bytes = len(data)
    byte_counts =[0]*256

    for byte in data:
        byte_counts[byte]+=1

    for count in byte_counts:
        if count == 0:
            continue
        probability = count / total_bytes
        entropy -= probability * math.log2(probability)
    return entropy

def calculate_section_entropies(pe):
    for section in pe.sections:
        section_data=section.get_data()
        entropy = calculate_entropy(section_data)
        return entropy

def data_directory(pe):
    return len(pe.OPTIONAL_HEADER.DATA_DIRECTORY)


def ex(pe):
    num_export_func = 0
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        export_table = pe.DIRECTORY_ENTRY_EXPORT
        num_export_table = export_table.struct.NumberOfFunctions
        num_export_func = export_table.struct.NumberOfNames
    return num_export_func


def ini_data(pe):
    initialized_data_size = 0
    for section in pe.sections:
        if section.Name.decode().strip('\x00') == ".rsrc":
            initialized_data_size = section.SizeOfRawData
            break
    return initialized_data_size

def get_dll_characteristics(pe):
    dll_characteristics = pe.OPTIONAL_HEADER.DllCharacteristics
    return dll_characteristics

def has_digital_signature(pe):
    if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
        security_entry = pe.DIRECTORY_ENTRY_SECURITY
        sec_addr = security_entry.VirtualAddress
        if security_entry.Size > 0:
            data = pe.write()[sec_addr + 8:]
            if len(data) > 0:
                try:
                    cert = x509.load_der_x509_certificate(data, default_backend())
                    cert.public_key().verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                        padding=cert.signature_algorithm.padding,
                        algorithm=cert.signature_algorithm.algorithm
                    )
                    return True  # Signature verified
                except:
                    return False  # Signature verification failed
    return False  # No security directory entry

       
            

def calculate_md5(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path,"rb") as file:
        for chunk in iter(lambda:file.read(4096),b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def get_architecture(pe):
    
    if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
        return "x86/32-bit"
    return "Unknown"


    
    

def main():
    args = sys.argv[1:]  # Get command-line arguments except the script name
    if not args:
        print("Usage: python script.py <folder_path>")
        return

    global folder_path
    folder_path = args[0]  # Get the first argument as folder_path
    
    for filename in os.listdir(folder_path):
        file_path = os.path.join(folder_path, filename)
        if os.path.isfile(file_path):
            print("File:", file_path)
            scan(file_path)




if __name__ =="__main__":

    main()
