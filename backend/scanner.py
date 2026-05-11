import hashlib
import os
import yara
import streamlit as st
from quarantineThreats import Quarantine
import shutil

# Assuming you have the class `Scanner` defined as provided in the initial code.
class Scanner:
    fileTypes = [".vbs", ".ps", ".ps1", ".rar", ".tmp", ".bas", ".bat", ".chm", ".cmd", ".com", ".cpl", ".crt", ".dll", ".exe", ".hta", ".js", ".lnk", ".msc", ".ocx", ".pcd", ".pif", ".pot", ".pdf", ".reg", ".scr", ".sct", ".sys", ".url", ".vb", ".vbe", ".wsc", ".wsf", ".wsh", ".ct", ".t", ".input", ".war",".jsp", ".jspx", ".php", ".asp", ".aspx", ".doc", ".docx", ".pdf", ".xls", ".xlsx", ".ppt", ".pptx", ".tmp", ".log", ".dump", ".pwd", ".w", ".txt", ".conf", ".cfg", ".conf", ".config", ".psd1", ".psm1", ".ps1xml", ".clixml", ".psc1", ".pssc", ".pl", ".www", ".rdp", ".jar", ".docm", ".sys", ".zip", ".tar",".msi"]

    def __init__(self,signatures,rootPath):
        import sys
        self.__signatures = signatures
        self.__rootPath = rootPath if not getattr(sys,'frozen',False) else "."
        self.quarantineData = {
            'configFileName':'quar_info',
            'configFilePath':self.__rootPath+'/config/',
            'defaults':{}
        }
        try:
            while not os.path.exists(self.__rootPath+"/compiledRules"):
                print("Waiting for resources to compile...")
            self.peid_rules = yara.load(self.__rootPath+"/compiledRules")
        except Exception as e:
            print(e)
        self.quar = Quarantine(self.quarantineData)

    def getFileHash(self, path):
        try:
            with open(path,'rb') as f:
                bytes = f.read()
                return hashlib.sha256(bytes).hexdigest()
        except (PermissionError, OSError):
            return "XYLENT_PERMISSION_ERROR"
    
    def scanFile(self, path):
        detectionSpace = "SAFE" 
        suspScore = 0
        isArchive = False
        fileExtension = os.path.splitext(path)[1]

        if fileExtension in self.fileTypes:
            hashToChk = self.getFileHash(path)
            if hashToChk == "XYLENT_PERMISSION_ERROR":
                return "SKIPPED"

            if fileExtension == ".zip" or fileExtension == ".tar":
                isArchive = True

            if not isArchive and (fileExtension == ".exe" or fileExtension == ".msi"):
                exeSigData = self.verifyExecutableSignature(path)
                suspScore += exeSigData['score']
                if suspScore >= 70:
                    detectionSpace = "Invalid Signature"

            if hashToChk != "" and suspScore < 70:
                for hash in self.__signatures:
                    if hash == str(hashToChk):
                        suspScore += 100
                        detectionSpace = "[S]" + self.__signatures[hash]

            if not isArchive and suspScore >= 70:
                detectionSpace = "[Malicious] - Invalid Signature"

            if isArchive:
                self.handleArchives(path)

            return detectionSpace
        return "SKIPPED"

    def handleArchives(self, path):
        archiveExtractPath = "./scanExtracts"
        if not os.path.exists(archiveExtractPath):
            os.mkdir(archiveExtractPath)
        shutil.unpack_archive(path, archiveExtractPath)
        self.scanFolders(archiveExtractPath)

    def scanFolders(self, location):
        directories = []
        if isinstance(location, str):
            for (dirpath, dirnames, filenames) in os.walk(location):
                directories += [os.path.join(dirpath, file) for file in filenames]

        scanReport = {}
        for file in directories:
            verdict = self.scanFile(file)
            if verdict:
                scanReport[file] = verdict
        return scanReport

# Streamlit app code

def main():
    st.title('Malware Scanner')
    st.markdown('Upload files or directories to scan for malware.')
    
    # Upload files
    uploaded_files = st.file_uploader("Choose files to scan", accept_multiple_files=True)

    # Show scan results
    if uploaded_files:
        st.write("Scanning files...")
        
        # Initialize the scanner (you can pass your signatures and path here)
        signatures = {}  # You would need to load your malware signatures here
        scanner = Scanner(signatures, '.')

        for uploaded_file in uploaded_files:
            file_path = f"./temp/{uploaded_file.name}"
            with open(file_path, 'wb') as f:
                f.write(uploaded_file.getbuffer())
            
            result = scanner.scanFile(file_path)
            st.write(f"File: {uploaded_file.name} - Scan Result: {result}")
    
    # Optional: Scan directories if needed (using the file uploader widget)
    scan_directory = st.text_input("Enter directory path to scan (e.g. /home/user/usb)")
    if scan_directory:
        if os.path.exists(scan_directory):
            scanner = Scanner(signatures, '.')
            scan_results = scanner.scanFolders(scan_directory)
            st.write(f"Scan Results for Directory '{scan_directory}':")
            st.write(scan_results)
        else:
            st.error("Directory not found.")
    
if __name__ == "__main__":
    main()
