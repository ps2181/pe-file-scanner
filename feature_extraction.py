import os
import csv
import pefile
import sys
import math
import hashlib
import argparse
import yaml
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed
from tqdm import tqdm
from cryptography import x509
from cryptography.hazmat.backends import default_backend

class PEScanner:
    def __init__(self, config_path='config.yaml'):
        self.config = self.load_config(config_path)
        self.results = []
        
    def load_config(self, config_path):
        """Load configuration from YAML file"""
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        return self.get_default_config()
    
    def get_default_config(self):
        """Return default configuration"""
        return {
            'scanner': {
                'workers': 4,
                'timeout': 30,
                'min_string_length': 4,
                'batch_size': 100
            }
        }
    
    def scan_file(self, file_path):
        """Scan a single PE file and extract features"""
        try:
            pe = pefile.PE(file_path)
            features = self.extract_features(pe, file_path)
            pe.close()
            return features
        except Exception as e:
            print(f"Error scanning {file_path}: {str(e)}")
            return None
    
    def extract_features(self, pe, file_path):
        """Extract all features from PE file"""
        features = {
            'filename': os.path.basename(file_path),
            'filepath': file_path
        }
        
        # Import analysis
        features['cnt_dll'], features['cnt_nondll'] = self.analyze_imports(pe)
        
        # String analysis
        features['str'] = self.count_strings(pe)
        
        # Entropy analysis
        features['entpy'] = self.calculate_avg_entropy(pe)
        
        # Data directories
        features['no_DD'] = len(pe.OPTIONAL_HEADER.DATA_DIRECTORY)
        
        # Export table
        features['EX'] = self.count_exports(pe)
        
        # Data sections
        features['init_data'] = self.get_initialized_data_size(pe)
        features['uninit_data'] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
        
        # DLL characteristics
        features['dll_char'] = pe.OPTIONAL_HEADER.DllCharacteristics
        
        # Digital signature
        features['digi_sign'] = 1 if self.has_digital_signature(pe) else 0
        
        # File hash
        features['md5'] = self.calculate_md5(file_path)
        features['sha256'] = self.calculate_sha256(file_path)
        
        # Architecture
        features['arch'] = 1 if self.get_architecture(pe) == "x86/32-bit" else 0
        
        # Code information
        features['size_code'] = pe.OPTIONAL_HEADER.SizeOfCode
        features['major_linker'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
        features['minor_linker'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
        
        # Additional features
        features['num_sections'] = pe.FILE_HEADER.NumberOfSections
        features['timestamp'] = pe.FILE_HEADER.TimeDateStamp
        features['has_resources'] = 1 if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') else 0
        features['has_tls'] = 1 if hasattr(pe, 'DIRECTORY_ENTRY_TLS') else 0
        features['file_size'] = os.path.getsize(file_path)
        
        return features
    
    def analyze_imports(self, pe):
        """Count DLL and non-DLL imports"""
        cnt_dll = 0
        cnt_nondll = 0
        
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                imported_dll = entry.dll.decode('utf-8', errors='ignore')
                if imported_dll.lower().endswith(".dll"):
                    cnt_dll += 1
                else:
                    cnt_nondll += 1
        
        return cnt_dll, cnt_nondll
    
    def count_strings(self, pe):
        """Count printable strings in PE sections"""
        total_strings = 0
        min_length = self.config['scanner']['min_string_length']
        
        for section in pe.sections:
            section_data = section.get_data()
            strings = self.extract_strings(section_data, min_length)
            total_strings += len(strings)
        
        return total_strings
    
    def extract_strings(self, data, min_length=4):
        """Extract printable strings from binary data"""
        strings = []
        current_string = ""
        
        for byte in data:
            if 0x20 <= byte <= 0x7E:
                current_string += chr(byte)
            else:
                if len(current_string) >= min_length:
                    strings.append(current_string)
                current_string = ""
        
        return strings
    
    def calculate_avg_entropy(self, pe):
        """Calculate average entropy across all sections"""
        entropies = []
        
        for section in pe.sections:
            section_data = section.get_data()
            entropy = self.calculate_entropy(section_data)
            entropies.append(entropy)
        
        return sum(entropies) / len(entropies) if entropies else 0
    
    def calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        if not data:
            return 0
        
        entropy = 0
        byte_counts = [0] * 256
        
        for byte in data:
            byte_counts[byte] += 1
        
        total_bytes = len(data)
        for count in byte_counts:
            if count == 0:
                continue
            probability = count / total_bytes
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def count_exports(self, pe):
        """Count number of exported functions"""
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            return pe.DIRECTORY_ENTRY_EXPORT.struct.NumberOfNames
        return 0
    
    def get_initialized_data_size(self, pe):
        """Get size of initialized data"""
        for section in pe.sections:
            if section.Name.decode('utf-8', errors='ignore').strip('\x00') == ".rsrc":
                return section.SizeOfRawData
        return 0
    
    def has_digital_signature(self, pe):
        """Check if PE has valid digital signature"""
        if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
            return pe.DIRECTORY_ENTRY_SECURITY.Size > 0
        return False
    
    def calculate_md5(self, file_path):
        """Calculate MD5 hash of file"""
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    
    def calculate_sha256(self, file_path):
        """Calculate SHA256 hash of file"""
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    
    def get_architecture(self, pe):
        """Determine PE architecture"""
        if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
            return "x86/32-bit"
        elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
            return "x64/64-bit"
        return "Unknown"
    
    def scan_folder(self, folder_path, parallel=True):
        """Scan all PE files in folder"""
        pe_files = []
        
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                if self.is_pe_file(file_path):
                    pe_files.append(file_path)
        
        print(f"Found {len(pe_files)} PE files to scan")
        
        if parallel:
            return self.scan_parallel(pe_files)
        else:
            return self.scan_sequential(pe_files)
    
    def is_pe_file(self, file_path):
        """Check if file is a valid PE file"""
        try:
            with open(file_path, 'rb') as f:
                return f.read(2) == b'MZ'
        except:
            return False
    
    def scan_parallel(self, file_paths):
        """Scan files in parallel using multiprocessing"""
        workers = self.config['scanner']['workers']
        results = []
        
        with ProcessPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(self.scan_file, fp): fp for fp in file_paths}
            
            with tqdm(total=len(file_paths), desc="Scanning files") as pbar:
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        results.append(result)
                    pbar.update(1)
        
        return results
    
    def scan_sequential(self, file_paths):
        """Scan files sequentially"""
        results = []
        
        for file_path in tqdm(file_paths, desc="Scanning files"):
            result = self.scan_file(file_path)
            if result:
                results.append(result)
        
        return results
    
    def save_to_csv(self, results, output_path='output.csv'):
        """Save results to CSV file"""
        if not results:
            print("No results to save")
            return
        
        keys = results[0].keys()
        
        with open(output_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(results)
        
        print(f"Results saved to {output_path}")

def main():
    parser = argparse.ArgumentParser(description='Advanced PE File Scanner')
    parser.add_argument('folder_path', help='Path to folder containing PE files')
    parser.add_argument('--workers', type=int, help='Number of parallel workers')
    parser.add_argument('--output', default='output.csv', help='Output CSV file')
    parser.add_argument('--sequential', action='store_true', help='Disable parallel processing')
    parser.add_argument('--config', default='config.yaml', help='Config file path')
    
    args = parser.parse_args()
    
    scanner = PEScanner(config_path=args.config)
    
    if args.workers:
        scanner.config['scanner']['workers'] = args.workers
    
    results = scanner.scan_folder(args.folder_path, parallel=not args.sequential)
    scanner.save_to_csv(results, args.output)

if __name__ == "__main__":
    main()