import sys
import os
import tempfile
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QLabel, QPushButton, QFileDialog, QTableWidget, QTableWidgetItem,
                             QTextEdit, QTabWidget, QComboBox, QCheckBox, QProgressBar,
                             QMessageBox, QSplitter, QGroupBox, QScrollArea, QLineEdit,
                             QHeaderView, QSizePolicy, QTreeWidget, QTreeWidgetItem, QFrame,
                             QToolBar, QAction, QMenu, QDialog, QDialogButtonBox, QFormLayout,
                             QSpinBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QColor, QTextCursor, QPalette, QIcon, QPixmap
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import matplotlib.pyplot as plt
import numpy as np

# Use the new modular backend
from raven.analyzer import PEAnalyzer
from raven.core import calculate_entropy, SUSPICIOUS_APIS

class AnalysisThread(QThread):
    """Thread for running analysis to prevent GUI freezing"""
    progress = pyqtSignal(int, str)
    finished = pyqtSignal(object)
    error = pyqtSignal(str)
    
    def __init__(self, file_path, full_analysis=True):
        super().__init__()
        self.file_path = file_path
        self.full_analysis = full_analysis
        self.analyzer = None
    
    def run(self):
        try:
            self.analyzer = PEAnalyzer(self.file_path)
            self.progress.emit(10, "Loading PE file...")
            
            # Use the new run_full_analysis method
            success = self.analyzer.run_full_analysis()
            
            if not success:
                self.error.emit("Failed to load PE file")
                return
            
            self.progress.emit(100, "Analysis complete!")
            self.finished.emit(self.analyzer)
            
        except Exception as e:
            self.error.emit(f"Analysis error: {str(e)}")

class EntropyGraph(FigureCanvas):
    """Widget for displaying entropy graph"""
    def __init__(self, parent=None, width=5, height=4, dpi=100):
        self.fig = Figure(figsize=(width, height), dpi=dpi)
        super().__init__(self.fig)
        self.setParent(parent)
        
        self.axes = self.fig.add_subplot(111)
        self.fig.tight_layout()
    
    def plot_entropy(self, sections):
        """Plot entropy data for sections"""
        self.axes.clear()
        
        names = [s['name'] for s in sections]
        entropies = [s['entropy'] for s in sections]
        
        # Create colors based on entropy values
        colors = []
        for entropy in entropies:
            if entropy > 7.5:
                colors.append('red')
            elif entropy > 6.5:
                colors.append('orange')
            else:
                colors.append('green')
        
        bars = self.axes.bar(names, entropies, color=colors, alpha=0.7)
        
        # Add threshold lines
        self.axes.axhline(y=7.5, color='r', linestyle='--', alpha=0.5, label='High Entropy Threshold')
        self.axes.axhline(y=6.5, color='y', linestyle='--', alpha=0.5, label='Medium Entropy Threshold')
        
        self.axes.set_ylabel('Entropy')
        self.axes.set_title('Section Entropy Analysis')
        self.axes.set_ylim(0, 8.5)
        
        # Rotate x-axis labels for better readability
        plt.setp(self.axes.get_xticklabels(), rotation=45, ha='right')
        
        # Add legend
        self.axes.legend()
        
        # Add value labels on top of bars
        for i, bar in enumerate(bars):
            height = bar.get_height()
            self.axes.text(bar.get_x() + bar.get_width()/2., height + 0.05,
                         f'{height:.2f}', ha='center', va='bottom', fontsize=8)
        
        self.draw()

class ExportDialog(QDialog):
    """Dialog for exporting analysis results"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Export Analysis Results")
        self.setModal(True)
        self.init_ui()
    
    def init_ui(self):
        layout = QFormLayout()
        
        self.format_combo = QComboBox()
        self.format_combo.addItems(["JSON", "Text", "HTML"])
        
        self.include_strings = QCheckBox("Include all strings")
        self.include_strings.setChecked(True)
        
        self.include_disassembly = QCheckBox("Include disassembly")
        self.include_disassembly.setChecked(False)
        
        self.string_min_length = QSpinBox()
        self.string_min_length.setRange(4, 20)
        self.string_min_length.setValue(4)
        self.string_min_length.setEnabled(False)
        
        self.include_strings.stateChanged.connect(
            lambda state: self.string_min_length.setEnabled(state == Qt.Checked)
        )
        
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        
        layout.addRow("Format:", self.format_combo)
        layout.addRow(self.include_strings)
        layout.addRow("Min string length:", self.string_min_length)
        layout.addRow(self.include_disassembly)
        layout.addRow(buttons)
        
        self.setLayout(layout)
    
    def get_options(self):
        return {
            'format': self.format_combo.currentText().lower(),
            'include_strings': self.include_strings.isChecked(),
            'string_min_length': self.string_min_length.value(),
            'include_disassembly': self.include_disassembly.isChecked()
        }

class RavenGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.analyzer = None
        self.current_file = None
        self.initUI()
    
    def initUI(self):
        self.setWindowTitle("Raven EXE Deconstructor")
        self.setGeometry(100, 100, 1400, 900)
        
        # Create toolbar
        self.toolbar = self.addToolBar('Main Toolbar')
        
        # Create actions
        export_action = QAction('Export', self)
        export_action.setShortcut('Ctrl+E')
        export_action.triggered.connect(self.export_analysis)
        
        # Add actions to toolbar
        self.toolbar.addAction(export_action)
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QVBoxLayout(central_widget)
        
        # Top panel with file selection
        top_panel = QHBoxLayout()
        
        self.file_label = QLabel("No file selected")
        self.file_label.setStyleSheet("QLabel { padding: 5px; background: #f0f0f0; border: 1px solid #ccc; }")
        
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self.browse_file)
        browse_btn.setStyleSheet("QPushButton { padding: 5px 10px; }")
        
        self.analyze_btn = QPushButton("Analyze")
        self.analyze_btn.clicked.connect(self.analyze_file)
        self.analyze_btn.setEnabled(False)
        self.analyze_btn.setStyleSheet("QPushButton { padding: 5px 10px; background: #4CAF50; color: white; }")
        
        top_panel.addWidget(self.file_label, 1)
        top_panel.addWidget(browse_btn)
        top_panel.addWidget(self.analyze_btn)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_label = QLabel()
        self.progress_label.setVisible(False)
        
        # Tab widget for different views
        self.tabs = QTabWidget()
        
        # Overview tab
        self.overview_tab = QWidget()
        self.setup_overview_tab()
        self.tabs.addTab(self.overview_tab, "Overview")
        
        # Sections tab
        self.sections_tab = QWidget()
        self.setup_sections_tab()
        self.tabs.addTab(self.sections_tab, "Sections")
        
        # Imports/Exports tab
        self.imports_tab = QWidget()
        self.setup_imports_tab()
        self.tabs.addTab(self.imports_tab, "Imports/Exports")
        
        # Strings tab
        self.strings_tab = QWidget()
        self.setup_strings_tab()
        self.tabs.addTab(self.strings_tab, "Strings")
        
        # Hex view tab
        self.hex_tab = QWidget()
        self.setup_hex_tab()
        self.tabs.addTab(self.hex_tab, "Hex View")
        
        # Functions tab
        self.functions_tab = QWidget()
        self.setup_functions_tab()
        self.tabs.addTab(self.functions_tab, "Functions")
        
        # Add widgets to main layout
        main_layout.addLayout(top_panel)
        main_layout.addWidget(self.progress_label)
        main_layout.addWidget(self.progress_bar)
        main_layout.addWidget(self.tabs)
        
        # Status bar
        self.statusBar().showMessage("Ready")
    
    def setup_overview_tab(self):
        layout = QVBoxLayout(self.overview_tab)
        
        # Splitter for resizable panels
        splitter = QSplitter(Qt.Vertical)
        
        # Risk assessment widget
        risk_widget = QGroupBox("Risk Assessment")
        risk_layout = QVBoxLayout()
        self.risk_label = QLabel("Not analyzed")
        self.risk_label.setAlignment(Qt.AlignCenter)
        self.risk_label.setStyleSheet("QLabel { font-size: 24px; padding: 20px; }")
        risk_layout.addWidget(self.risk_label)
        risk_widget.setLayout(risk_layout)
        
        # Entropy graph
        entropy_widget = QGroupBox("Entropy Analysis")
        entropy_layout = QVBoxLayout()
        self.entropy_graph = EntropyGraph(entropy_widget, width=8, height=4, dpi=100)
        entropy_layout.addWidget(self.entropy_graph)
        entropy_widget.setLayout(entropy_layout)
        
        # Basic info widget
        info_widget = QGroupBox("Basic Information")
        info_layout = QVBoxLayout()
        self.info_text = QTextEdit()
        self.info_text.setReadOnly(True)
        info_layout.addWidget(self.info_text)
        info_widget.setLayout(info_layout)
        
        # Findings widget
        findings_widget = QGroupBox("Key Findings")
        findings_layout = QVBoxLayout()
        self.findings_text = QTextEdit()
        self.findings_text.setReadOnly(True)
        findings_layout.addWidget(self.findings_text)
        findings_widget.setLayout(findings_layout)
        
        # Add widgets to splitter
        splitter.addWidget(risk_widget)
        splitter.addWidget(entropy_widget)
        splitter.addWidget(info_widget)
        splitter.addWidget(findings_widget)
        splitter.setSizes([100, 300, 300, 300])
        
        layout.addWidget(splitter)
    
    def setup_sections_tab(self):
        layout = QVBoxLayout(self.sections_tab)
        
        self.sections_table = QTableWidget()
        self.sections_table.setColumnCount(8)
        self.sections_table.setHorizontalHeaderLabels([
            "Name", "Virtual Address", "Virtual Size", "Raw Size", 
            "Entropy", "Flags", "Suspicious", "Anomalies"
        ])
        self.sections_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.sections_table)
    
    def setup_imports_tab(self):
        layout = QVBoxLayout(self.imports_tab)
        
        # Tab widget for imports and exports
        imports_exports_tabs = QTabWidget()
        
        # Imports tab
        imports_tab = QWidget()
        imports_layout = QVBoxLayout(imports_tab)
        self.imports_tree = QTreeWidget()
        self.imports_tree.setHeaderLabels(["DLL", "Function", "Status"])
        imports_layout.addWidget(self.imports_tree)
        imports_exports_tabs.addTab(imports_tab, "Imports")
        
        # Exports tab
        exports_tab = QWidget()
        exports_layout = QVBoxLayout(exports_tab)
        self.exports_table = QTableWidget()
        self.exports_table.setColumnCount(3)
        self.exports_table.setHorizontalHeaderLabels(["Name", "Address", "Ordinal"])
        exports_layout.addWidget(self.exports_table)
        imports_exports_tabs.addTab(exports_tab, "Exports")
        
        layout.addWidget(imports_exports_tabs)
    
    def setup_strings_tab(self):
        layout = QVBoxLayout(self.strings_tab)
        
        # Filter controls
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter:"))
        
        self.string_filter = QComboBox()
        self.string_filter.addItems(["All", "URLs", "File Paths", "Registry Keys", 
                                   "Executables", "Suspicious", "IP Addresses", "Domains", "Crypto Wallets"])
        self.string_filter.currentTextChanged.connect(self.filter_strings)
        filter_layout.addWidget(self.string_filter)
        
        self.string_search = QLineEdit()
        self.string_search.setPlaceholderText("Search strings...")
        self.string_search.textChanged.connect(self.filter_strings)
        filter_layout.addWidget(self.string_search)
        
        export_btn = QPushButton("Export Strings")
        export_btn.clicked.connect(self.export_strings)
        filter_layout.addWidget(export_btn)
        
        layout.addLayout(filter_layout)
        
        # Strings table
        self.strings_table = QTableWidget()
        self.strings_table.setColumnCount(2)
        self.strings_table.setHorizontalHeaderLabels(["Type", "String"])
        self.strings_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        layout.addWidget(self.strings_table)
    
    def setup_hex_tab(self):
        layout = QVBoxLayout(self.hex_tab)
        
        self.hex_text = QTextEdit()
        self.hex_text.setReadOnly(True)
        self.hex_text.setFont(QFont("Courier", 10))
        layout.addWidget(self.hex_text)
    
    def setup_functions_tab(self):
        layout = QVBoxLayout(self.functions_tab)
        
        self.functions_table = QTableWidget()
        self.functions_table.setColumnCount(4)
        self.functions_table.setHorizontalHeaderLabels(["Address", "Size", "Section", "API Calls"])
        self.functions_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.functions_table)
    
    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Executable File", "", 
            "Executable Files (*.exe *.dll *.sys);;All Files (*)"
        )
        
        if file_path:
            self.current_file = file_path
            self.file_label.setText(file_path)
            self.analyze_btn.setEnabled(True)
    
    def analyze_file(self):
        if not self.current_file:
            return
        
        # Reset UI
        self.reset_ui()
        
        # Show progress
        self.progress_bar.setVisible(True)
        self.progress_label.setVisible(True)
        self.analyze_btn.setEnabled(False)
        
        # Create and start analysis thread
        self.analysis_thread = AnalysisThread(self.current_file)
        self.analysis_thread.progress.connect(self.update_progress)
        self.analysis_thread.finished.connect(self.analysis_finished)
        self.analysis_thread.error.connect(self.analysis_error)
        self.analysis_thread.start()
    
    def update_progress(self, value, message):
        self.progress_bar.setValue(value)
        self.progress_label.setText(message)
        self.statusBar().showMessage(message)
    
    def analysis_finished(self, analyzer):
        self.analyzer = analyzer
        self.progress_bar.setVisible(False)
        self.progress_label.setVisible(False)
        self.analyze_btn.setEnabled(True)
        
        # Update UI with results
        self.update_overview_tab()
        self.update_sections_tab()
        self.update_imports_tab()
        self.update_strings_tab()
        self.update_hex_view()
        self.update_functions_tab()
        
        self.statusBar().showMessage("Analysis complete")
    
    def analysis_error(self, error_message):
        self.progress_bar.setVisible(False)
        self.progress_label.setVisible(False)
        self.analyze_btn.setEnabled(True)
        
        QMessageBox.critical(self, "Analysis Error", error_message)
        self.statusBar().showMessage("Analysis failed")
    
    def reset_ui(self):
        self.info_text.clear()
        self.findings_text.clear()
        self.sections_table.setRowCount(0)
        self.imports_tree.clear()
        self.exports_table.setRowCount(0)
        self.strings_table.setRowCount(0)
        self.hex_text.clear()
        self.functions_table.setRowCount(0)
        self.risk_label.setText("Not analyzed")
        self.risk_label.setStyleSheet("QLabel { font-size: 24px; padding: 20px; background: #f0f0f0; }")
    
    def update_overview_tab(self):
        if not self.analyzer:
            return
        
        # Update risk label
        risk = self.analyzer.results.get('risk', 'Unknown')
        risk_color = "#ff0000" if risk in ['Critical', 'High'] else "#ffaa00" if risk == 'Medium' else "#00aa00"
        self.risk_label.setText(f"Risk Level: {risk}")
        self.risk_label.setStyleSheet(f"QLabel {{ font-size: 24px; padding: 20px; background: {risk_color}; color: white; }}")
        
        # Update entropy graph
        sections = self.analyzer.results.get('sections', [])
        self.entropy_graph.plot_entropy(sections)
        
        # Update basic info
        info_text = []
        for key, value in self.analyzer.results['basic_info'].items():
            info_text.append(f"<b>{key.replace('_', ' ').title()}:</b> {value}")
        
        # Add hashes
        info_text.append("<br><b>File Hashes:</b>")
        for algo, hash_val in self.analyzer.results['file_hashes'].items():
            info_text.append(f"  {algo.upper()}: {hash_val}")
        
        self.info_text.setHtml("<br>".join(info_text))
        
        # Update findings
        findings = []
        
        # Risk score and factors
        risk_score = self.analyzer.results.get('risk_score', 0)
        risk_factors = self.analyzer.results.get('risk_factors', [])
        
        if risk_score > 0:
            findings.append(f"<b style='color: blue;'>Risk Score:</b> {risk_score}")
            if risk_factors:
                findings.append("<b style='color: blue;'>Risk Factors:</b>")
                for factor in risk_factors:
                    findings.append(f"• {factor}")
        
        # Suspicious findings
        suspicious = self.analyzer.results.get('suspicious_findings', [])
        if suspicious:
            findings.append("<br><b style='color: red;'>Suspicious Findings:</b>")
            for finding in suspicious:
                findings.append(f"• {finding.get('message', 'Unknown finding')}")
        
        # Anomalies
        anomalies = self.analyzer.results.get('anomalies', [])
        if anomalies:
            findings.append("<br><b style='color: orange;'>Structural Anomalies:</b>")
            for anomaly in anomalies:
                findings.append(f"• {anomaly.get('message', 'Unknown anomaly')}")
        
        # Overlay
        overlay = self.analyzer.results.get('overlay')
        if overlay:
            findings.append(f"<br><b style='color: blue;'>Overlay Data:</b> {overlay.get('message')}")
        
        # Packer info
        packer_info = self.analyzer.results.get('packer_info', {})
        if packer_info.get('signatures') or packer_info.get('patterns'):
            findings.append("<br><b style='color: purple;'>Packer Detection:</b>")
            if packer_info.get('signatures'):
                findings.append(f"• Signatures: {', '.join(packer_info['signatures'])}")
            if packer_info.get('patterns'):
                findings.append(f"• Patterns: {', '.join(packer_info['patterns'])}")
        
        self.findings_text.setHtml("<br>".join(findings) if findings else "No significant findings")
    
    def update_sections_tab(self):
        if not self.analyzer:
            return
        
        sections = self.analyzer.results.get('sections', [])
        self.sections_table.setRowCount(len(sections))
        
        for row, section in enumerate(sections):
            # Name
            self.sections_table.setItem(row, 0, QTableWidgetItem(section['name']))
            
            # Virtual address
            self.sections_table.setItem(row, 1, QTableWidgetItem(f"0x{section['virtual_address']:X}"))
            
            # Virtual size
            self.sections_table.setItem(row, 2, QTableWidgetItem(f"0x{section['virtual_size']:X}"))
            
            # Raw size
            self.sections_table.setItem(row, 3, QTableWidgetItem(f"0x{section['raw_size']:X}"))
            
            # Entropy with color coding
            entropy_item = QTableWidgetItem(f"{section['entropy']:.2f}")
            if section['entropy'] > 7.5:
                entropy_item.setBackground(QColor(255, 200, 200))  # Light red
            elif section['entropy'] > 6.5:
                entropy_item.setBackground(QColor(255, 255, 200))  # Light yellow
            self.sections_table.setItem(row, 4, entropy_item)
            
            # Flags
            self.sections_table.setItem(row, 5, QTableWidgetItem(section['characteristics_human']))
            
            # Suspicious
            suspicious_item = QTableWidgetItem("Yes" if section['is_suspicious'] else "No")
            if section['is_suspicious']:
                suspicious_item.setBackground(QColor(255, 200, 200))
            self.sections_table.setItem(row, 6, suspicious_item)
            
            # Anomalies
            anomalies_text = ", ".join(section['anomalies']) if section['anomalies'] else "None"
            anomalies_item = QTableWidgetItem(anomalies_text)
            if section['anomalies']:
                anomalies_item.setBackground(QColor(255, 220, 200))
            self.sections_table.setItem(row, 7, anomalies_item)
    
    def update_imports_tab(self):
        if not self.analyzer:
            return
        
        # Imports
        imports = self.analyzer.results.get('imports', {})
        self.imports_tree.clear()
        
        suspicious_apis = []
        for suspicious_dll, apis in SUSPICIOUS_APIS.items():
            for api in apis:
                suspicious_apis.append(f"{suspicious_dll.lower()}.{api}")
        
        for dll, functions in imports.items():
            dll_item = QTreeWidgetItem(self.imports_tree, [dll, "", ""])
            
            for func in functions:
                status = "Suspicious" if f"{dll}.{func}" in suspicious_apis else "Normal"
                func_item = QTreeWidgetItem(dll_item, [dll, func, status])
                
                if status == "Suspicious":
                    func_item.setBackground(2, QColor(255, 200, 200))
            
            dll_item.setExpanded(True)
        
        # Exports
        exports = self.analyzer.results.get('exports', {}).get('functions', [])
        self.exports_table.setRowCount(len(exports))
        
        for row, export in enumerate(exports):
            self.exports_table.setItem(row, 0, QTableWidgetItem(export.get('name', 'N/A')))
            self.exports_table.setItem(row, 1, QTableWidgetItem(f"0x{export.get('address', 0):X}"))
            self.exports_table.setItem(row, 2, QTableWidgetItem(str(export.get('ordinal', 'N/A'))))
    
    def update_strings_tab(self):
        if not self.analyzer:
            return
        
        self.all_strings = []
        strings_data = self.analyzer.results.get('strings', {})
        
        for s_type, strings in strings_data.items():
            for s in strings:
                self.all_strings.append((s_type, s))
        
        self.filter_strings()
    
    def filter_strings(self):
        if not hasattr(self, 'all_strings'):
            return
        
        filter_type = self.string_filter.currentText().lower().replace(' ', '_')
        search_text = self.string_search.text().lower()
        
        filtered_strings = []
        for s_type, s in self.all_strings:
            # Apply type filter
            if filter_type != "all" and s_type != filter_type:
                continue
            
            # Apply search filter
            if search_text and search_text not in s.lower():
                continue
            
            filtered_strings.append((s_type, s))
        
        # Update table
        self.strings_table.setRowCount(len(filtered_strings))
        
        for row, (s_type, s) in enumerate(filtered_strings):
            # Type with color coding
            type_item = QTableWidgetItem(s_type)
            if s_type in ['suspicious', 'url', 'executable', 'ip_address', 'crypto_wallet']:
                type_item.setBackground(QColor(255, 200, 200))
            elif s_type != 'other':
                type_item.setBackground(QColor(255, 255, 200))
            self.strings_table.setItem(row, 0, type_item)
            
            # String value
            self.strings_table.setItem(row, 1, QTableWidgetItem(s))
    
    def update_hex_view(self):
        if not self.analyzer or not self.analyzer.pe:
            return
        
        try:
            # Read first 4KB of the file for hex view
            with open(self.current_file, 'rb') as f:
                data = f.read(4096)
            
            hex_text = []
            for i in range(0, min(len(data), 4096), 16):
                # Offset
                hex_text.append(f"{i:08X}  ")
                
                # Hex bytes
                hex_bytes = []
                for j in range(16):
                    if i + j < len(data):
                        hex_bytes.append(f"{data[i+j]:02X}")
                    else:
                        hex_bytes.append("  ")
                
                hex_text.append(" ".join(hex_bytes[:8]))
                hex_text.append("  ")
                hex_text.append(" ".join(hex_bytes[8:]))
                hex_text.append("  ")
                
                # ASCII representation
                ascii_repr = []
                for j in range(16):
                    if i + j < len(data):
                        byte = data[i+j]
                        if 32 <= byte <= 126:
                            ascii_repr.append(chr(byte))
                        else:
                            ascii_repr.append(".")
                    else:
                        ascii_repr.append(" ")
                
                hex_text.append(f"  {''.join(ascii_repr)}\n")
            
            self.hex_text.setPlainText("".join(hex_text))
        except Exception as e:
            self.hex_text.setPlainText(f"Error reading file: {str(e)}")
    
    def update_functions_tab(self):
        if not self.analyzer:
            return
        
        functions = self.analyzer.results.get('functions', [])
        api_calls = self.analyzer.results.get('api_calls', [])
        
        self.functions_table.setRowCount(len(functions))
        
        for row, func in enumerate(functions):
            # Address
            self.functions_table.setItem(row, 0, QTableWidgetItem(f"0x{func['start']:X}"))
            
            # Size
            self.functions_table.setItem(row, 1, QTableWidgetItem(f"{func['size']} bytes"))
            
            # Section
            self.functions_table.setItem(row, 2, QTableWidgetItem(func['section']))
            
            # API calls in this function
            func_api_calls = [f"{api['dll']}!{api['api']}" for api in api_calls 
                             if func['start'] <= api['address'] <= func['end']]
            api_text = ", ".join(func_api_calls) if func_api_calls else "None"
            self.functions_table.setItem(row, 3, QTableWidgetItem(api_text))
    
    def export_analysis(self):
        """Export analysis results to file"""
        if not self.analyzer:
            QMessageBox.warning(self, "Export Error", "No analysis results to export")
            return
        
        dialog = ExportDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            options = dialog.get_options()
            
            file_path, _ = QFileDialog.getSaveFileName(
                self, "Save Analysis Report", "", 
                f"{options['format'].upper()} Files (*.{options['format']})"
            )
            
            if file_path:
                try:
                    # Use the analyzer's built-in save method
                    success = self.analyzer.save_report(file_path, options['format'])
                    
                    if success:
                        QMessageBox.information(self, "Export Successful", f"Analysis exported to {file_path}")
                    else:
                        QMessageBox.critical(self, "Export Error", "Failed to export analysis")
                except Exception as e:
                    QMessageBox.critical(self, "Export Error", f"Failed to export analysis: {str(e)}")
    
    def export_strings(self):
        """Export strings to file"""
        if not hasattr(self, 'all_strings') or not self.all_strings:
            QMessageBox.warning(self, "Export Error", "No strings to export")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Strings", "", "Text Files (*.txt);;All Files (*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    for s_type, s in self.all_strings:
                        f.write(f"[{s_type}] {s}\n")
                QMessageBox.information(self, "Success", "Strings exported successfully")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export strings: {str(e)}")

def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')  # Modern style
    
    # Set application info
    app.setApplicationName("Raven EXE Deconstructor")
    app.setApplicationVersion("1.0")
    
    window = RavenGUI()
    window.show()
    
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
