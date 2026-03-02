"""
Pattern Import/Export System
Supports bulk import of existing patterns and export for backup/sharing
"""

import json
import csv
import os
import re
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple

class PatternImportExport:
    """Handles pattern import/export in multiple formats"""
    
    def __init__(self, pattern_manager):
        self.pattern_manager = pattern_manager
        self.supported_formats = ['json', 'csv', 'txt', 'legacy']
        
    def import_patterns_from_file(self, file_path: str, file_format: str = 'auto') -> Tuple[bool, str, Dict]:
        """Import patterns from various file formats"""
        
        if not os.path.exists(file_path):
            return False, f"File not found: {file_path}", {}
            
        # Auto-detect format if needed
        if file_format == 'auto':
            file_format = self._detect_file_format(file_path)
            
        try:
            if file_format == 'json':
                return self._import_json_patterns(file_path)
            elif file_format == 'csv':
                return self._import_csv_patterns(file_path)
            elif file_format == 'txt':
                return self._import_text_patterns(file_path)
            elif file_format == 'legacy':
                return self._import_legacy_patterns(file_path)
            else:
                return False, f"Unsupported format: {file_format}", {}
                
        except Exception as e:
            return False, f"Import error: {str(e)}", {}
    
    def export_patterns_to_file(self, file_path: str, file_format: str, components: List[str] = None) -> Tuple[bool, str]:
        """Export patterns to various file formats"""
        
        try:
            if file_format == 'json':
                return self._export_json_patterns(file_path, components)
            elif file_format == 'csv':
                return self._export_csv_patterns(file_path, components)
            elif file_format == 'txt':
                return self._export_text_patterns(file_path, components)
            else:
                return False, f"Unsupported export format: {file_format}"
                
        except Exception as e:
            return False, f"Export error: {str(e)}"
    
    def _detect_file_format(self, file_path: str) -> str:
        """Auto-detect file format based on extension and content"""
        _, ext = os.path.splitext(file_path.lower())
        
        if ext == '.json':
            return 'json'
        elif ext == '.csv':
            return 'csv'
        elif ext in ['.txt', '.log']:
            # Try to determine if it's structured text or legacy format
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    if 'ownership_patterns' in content or 'thunder_plugin' in content:
                        return 'legacy'
                    else:
                        return 'txt'
            except:
                return 'txt'
        else:
            return 'txt'
    
    def _import_json_patterns(self, file_path: str) -> Tuple[bool, str, Dict]:
        """Import patterns from JSON format"""
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        imported_count = 0
        import_summary = {'new': 0, 'updated': 0, 'skipped': 0, 'errors': []}
        
        # Handle different JSON structures
        if 'patterns' in data and isinstance(data['patterns'], dict):
            # New format: component-based structure
            for component_key, component_data in data['patterns'].items():
                if 'patterns' in component_data:
                    for pattern_group_name, pattern_group in component_data['patterns'].items():
                        if 'patterns' in pattern_group:
                            for pattern_info in pattern_group['patterns']:
                                success, message = self._add_pattern_from_import(pattern_info, component_key)
                                if success:
                                    import_summary['new'] += 1
                                else:
                                    import_summary['errors'].append(message)
                                imported_count += 1
        
        elif isinstance(data, list):
            # Array format: list of patterns
            for pattern_info in data:
                component = pattern_info.get('component', 'thunder')
                success, message = self._add_pattern_from_import(pattern_info, component)
                if success:
                    import_summary['new'] += 1
                else:
                    import_summary['errors'].append(message)
                imported_count += 1
        
        return True, f"Imported {imported_count} patterns", import_summary
    
    def _import_csv_patterns(self, file_path: str) -> Tuple[bool, str, Dict]:
        """Import patterns from CSV format"""
        imported_count = 0
        import_summary = {'new': 0, 'updated': 0, 'skipped': 0, 'errors': []}
        
        with open(file_path, 'r', encoding='utf-8', newline='') as csvfile:
            # Try to detect if file has headers
            sample = csvfile.read(1024)
            csvfile.seek(0)
            
            has_header = csv.Sniffer().has_header(sample)
            reader = csv.reader(csvfile)
            
            if has_header:
                headers = next(reader)
                # Map common header variations
                header_mapping = self._create_csv_header_mapping(headers)
            else:
                # Assume standard order: component, pattern, description, confidence, category
                header_mapping = {
                    'component': 0,
                    'pattern': 1, 
                    'description': 2,
                    'confidence': 3,
                    'category': 4
                }
            
            for row_num, row in enumerate(reader, start=2 if has_header else 1):
                try:
                    if len(row) < 3:  # Need at least component, pattern, description
                        continue
                        
                    pattern_info = {
                        'component': row[header_mapping.get('component', 0)],
                        'pattern': row[header_mapping.get('pattern', 1)],
                        'description': row[header_mapping.get('description', 2)],
                        'confidence': row[header_mapping.get('confidence', 3)] if len(row) > 3 else 'medium',
                        'category': row[header_mapping.get('category', 4)] if len(row) > 4 else 'imported'
                    }
                    
                    component = pattern_info['component']
                    success, message = self._add_pattern_from_import(pattern_info, component)
                    if success:
                        import_summary['new'] += 1
                    else:
                        import_summary['errors'].append(f"Row {row_num}: {message}")
                    imported_count += 1
                    
                except Exception as e:
                    import_summary['errors'].append(f"Row {row_num}: {str(e)}")
        
        return True, f"Imported {imported_count} patterns from CSV", import_summary
    
    def _import_text_patterns(self, file_path: str) -> Tuple[bool, str, Dict]:
        """Import patterns from plain text format"""
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        import_summary = {'new': 0, 'updated': 0, 'skipped': 0, 'errors': []}
        
        # Try to parse different text formats
        patterns_found = []
        
        # Format 1: Component: Pattern - Description
        format1_matches = re.findall(r'^(\w+):\s*(.+?)\s*-\s*(.+)$', content, re.MULTILINE)
        for component, pattern, description in format1_matches:
            patterns_found.append({
                'component': component.lower(),
                'pattern': pattern.strip(),
                'description': description.strip(),
                'confidence': 'medium',
                'category': 'text_import'
            })
        
        # Format 2: Pattern | Description | Component
        format2_matches = re.findall(r'^(.+?)\s*\|\s*(.+?)\s*\|\s*(.+?)$', content, re.MULTILINE)
        for pattern, description, component in format2_matches:
            patterns_found.append({
                'component': component.strip().lower(),
                'pattern': pattern.strip(),
                'description': description.strip(),
                'confidence': 'medium',
                'category': 'text_import'
            })
        
        # Format 3: Just patterns (assume Thunder)
        if not patterns_found:
            lines = [line.strip() for line in content.split('\n') if line.strip()]
            for line in lines:
                if self._looks_like_regex_pattern(line):
                    patterns_found.append({
                        'component': 'thunder',
                        'pattern': line,
                        'description': f'Imported pattern: {line[:50]}...',
                        'confidence': 'medium',
                        'category': 'text_import'
                    })
        
        # Import found patterns
        for pattern_info in patterns_found:
            component = pattern_info['component']
            success, message = self._add_pattern_from_import(pattern_info, component)
            if success:
                import_summary['new'] += 1
            else:
                import_summary['errors'].append(message)
        
        return True, f"Imported {len(patterns_found)} patterns from text", import_summary
    
    def _import_legacy_patterns(self, file_path: str) -> Tuple[bool, str, Dict]:
        """Import patterns from legacy Python code format"""
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        import_summary = {'new': 0, 'updated': 0, 'skipped': 0, 'errors': []}
        
        # Parse Python-like pattern definitions
        # Look for patterns like: 'pattern_name': [(r'regex', 'description', 'confidence'), ...]
        pattern_blocks = re.findall(
            r"'([^']+)':\s*\[\s*((?:(?:\([^)]+\),?\s*)+))\]", 
            content, 
            re.MULTILINE | re.DOTALL
        )
        
        for category_name, patterns_text in pattern_blocks:
            # Extract individual patterns
            pattern_matches = re.findall(
                r"\(\s*r?['\"]([^'\"]+)['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*(?:,\s*['\"]([^'\"]+)['\"])?\s*\)",
                patterns_text
            )
            
            # Determine component based on category name
            component = self._map_legacy_category_to_component(category_name)
            
            for pattern_match in pattern_matches:
                regex_pattern = pattern_match[0]
                description = pattern_match[1]
                confidence = pattern_match[2] if len(pattern_match) > 2 and pattern_match[2] else 'medium'
                
                pattern_info = {
                    'component': component,
                    'pattern': regex_pattern,
                    'description': description,
                    'confidence': confidence,
                    'category': f'legacy_{category_name}'
                }
                
                success, message = self._add_pattern_from_import(pattern_info, component)
                if success:
                    import_summary['new'] += 1
                else:
                    import_summary['errors'].append(message)
        
        total_imported = import_summary['new']
        return True, f"Imported {total_imported} legacy patterns", import_summary
    
    def _add_pattern_from_import(self, pattern_info: Dict, component: str) -> Tuple[bool, str]:
        """Add a single pattern from import data"""
        try:
            # Validate required fields
            if 'pattern' not in pattern_info or 'description' not in pattern_info:
                return False, "Missing required fields (pattern, description)"
            
            # Validate regex
            try:
                re.compile(pattern_info['pattern'])
            except re.error as e:
                return False, f"Invalid regex: {e}"
            
            # Normalize component name
            component = self._normalize_component_name(component)
            
            # Add pattern using pattern manager
            success, message = self.pattern_manager.add_user_pattern(
                component=component,
                pattern=pattern_info['pattern'],
                description=pattern_info['description'],
                confidence=pattern_info.get('confidence', 'medium'),
                category=pattern_info.get('category', 'imported')
            )
            
            return success, message
            
        except Exception as e:
            return False, f"Error adding pattern: {str(e)}"
    
    def _export_json_patterns(self, file_path: str, components: List[str] = None) -> Tuple[bool, str]:
        """Export patterns to JSON format"""
        export_data = {}
        
        for component_key, component_data in self.pattern_manager.loaded_patterns.items():
            if components and component_key not in components:
                continue
                
            export_data[component_key] = component_data
        
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        
        return True, f"Exported patterns to {file_path}"
    
    def _export_csv_patterns(self, file_path: str, components: List[str] = None) -> Tuple[bool, str]:
        """Export patterns to CSV format"""
        
        with open(file_path, 'w', encoding='utf-8', newline='') as csvfile:
            writer = csv.writer(csvfile)
            
            # Write header
            writer.writerow(['Component', 'Pattern', 'Description', 'Confidence', 'Category', 'Team', 'Created', 'Added By'])
            
            pattern_count = 0
            for component_key, component_data in self.pattern_manager.loaded_patterns.items():
                if components and component_key not in components:
                    continue
                    
                if 'patterns' in component_data:
                    for pattern_group_name, pattern_group in component_data['patterns'].items():
                        if 'patterns' in pattern_group:
                            for pattern_info in pattern_group['patterns']:
                                writer.writerow([
                                    component_key,
                                    pattern_info['pattern'],
                                    pattern_info['description'],
                                    pattern_info['confidence'],
                                    pattern_info.get('category', ''),
                                    pattern_info.get('escalation_team', ''),
                                    pattern_info.get('created_date', ''),
                                    pattern_info.get('added_by', '')
                                ])
                                pattern_count += 1
        
        return True, f"Exported {pattern_count} patterns to CSV: {file_path}"
    
    def _export_text_patterns(self, file_path: str, components: List[str] = None) -> Tuple[bool, str]:
        """Export patterns to human-readable text format"""
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write("WPE Framework Crash Analysis Patterns\n")
            f.write("=" * 50 + "\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            pattern_count = 0
            for component_key, component_data in self.pattern_manager.loaded_patterns.items():
                if components and component_key not in components:
                    continue
                    
                f.write(f"\n{component_key.upper().replace('_', ' ')} PATTERNS\n")
                f.write("-" * 40 + "\n")
                f.write(f"Description: {component_data.get('metadata', {}).get('description', 'N/A')}\n\n")
                
                if 'patterns' in component_data:
                    for pattern_group_name, pattern_group in component_data['patterns'].items():
                        if 'patterns' in pattern_group and pattern_group['patterns']:
                            f.write(f"  {pattern_group_name.replace('_', ' ').title()}:\n")
                            
                            for i, pattern_info in enumerate(pattern_group['patterns'], 1):
                                f.write(f"    {i}. {pattern_info['description']}\n")
                                f.write(f"       Pattern: {pattern_info['pattern']}\n")
                                f.write(f"       Confidence: {pattern_info['confidence']}\n")
                                f.write(f"       Team: {pattern_info.get('escalation_team', 'N/A')}\n\n")
                                pattern_count += 1
            
            f.write(f"\nTotal patterns: {pattern_count}\n")
        
        return True, f"Exported {pattern_count} patterns to text: {file_path}"
    
    def _create_csv_header_mapping(self, headers: List[str]) -> Dict[str, int]:
        """Create mapping from header names to column indices"""
        mapping = {}
        
        for i, header in enumerate(headers):
            header_lower = header.lower().strip()
            if header_lower in ['component', 'comp']:
                mapping['component'] = i
            elif header_lower in ['pattern', 'regex', 'regexp']:
                mapping['pattern'] = i
            elif header_lower in ['description', 'desc', 'name']:
                mapping['description'] = i
            elif header_lower in ['confidence', 'conf', 'level']:
                mapping['confidence'] = i
            elif header_lower in ['category', 'cat', 'type']:
                mapping['category'] = i
        
        return mapping
    
    def _looks_like_regex_pattern(self, line: str) -> bool:
        """Check if a line looks like a regular expression pattern"""
        regex_indicators = [
            r'\.\*', r'\+', r'\?', r'\[', r'\(', r'\{', 
            r'\\s', r'\\d', r'\\w', r'\|'
        ]
        
        return any(indicator in line for indicator in regex_indicators)
    
    def _map_legacy_category_to_component(self, category_name: str) -> str:
        """Map legacy category names to component names"""
        category_lower = category_name.lower()
        
        if 'plugin' in category_lower:
            return 'thunder'
        elif 'core' in category_lower or 'thunder' in category_lower:
            return 'thunder'
        elif 'hal' in category_lower or 'manager' in category_lower:
            return 'hal'
        elif 'iarm' in category_lower:
            return 'iarm'
        elif 'media' in category_lower or 'rmf' in category_lower:
            return 'media'
        elif 'sec' in category_lower or 'auth' in category_lower:
            return 'security'
        elif 'network' in category_lower or 'tr069' in category_lower:
            return 'network'
        elif 'system' in category_lower or 'service' in category_lower:
            return 'system'
        else:
            return 'thunder'  # Default fallback
    
    def _normalize_component_name(self, component: str) -> str:
        """Normalize component name to standard format"""
        component_lower = component.lower().strip()
        
        normalization_map = {
            'thunder': 'thunder',
            'wpe': 'thunder',
            'wpeframework': 'thunder',
            'hal': 'hal',
            'hardware': 'hal',
            'iarm': 'iarm', 
            'bus': 'iarm',
            'media': 'media',
            'rmf': 'media',
            'streaming': 'media',
            'security': 'security',
            'sec': 'security',
            'auth': 'security',
            'drm': 'security',
            'network': 'network',
            'net': 'network',
            'tr069': 'network',
            'system': 'system',
            'sys': 'system',
            'service': 'system'
        }
        
        return normalization_map.get(component_lower, 'thunder')
    
    def bulk_import_thunder_patterns(self, patterns_dict: Dict) -> Tuple[bool, str, Dict]:
        """Specialized method for bulk importing Thunder patterns"""
        import_summary = {'new': 0, 'updated': 0, 'skipped': 0, 'errors': []}
        
        for category, patterns in patterns_dict.items():
            component = 'thunder'  # All go to Thunder component
            
            for pattern_data in patterns:
                if isinstance(pattern_data, tuple) and len(pattern_data) >= 2:
                    pattern = pattern_data[0]
                    description = pattern_data[1]
                    confidence = pattern_data[2] if len(pattern_data) > 2 else 'medium'
                    
                    pattern_info = {
                        'component': component,
                        'pattern': pattern,
                        'description': description,
                        'confidence': confidence,
                        'category': f'thunder_{category}'
                    }
                    
                    success, message = self._add_pattern_from_import(pattern_info, component)
                    if success:
                        import_summary['new'] += 1
                    else:
                        import_summary['errors'].append(f"{category}: {message}")
        
        return True, f"Bulk imported {import_summary['new']} Thunder patterns", import_summary
    
    def create_import_template(self, template_format: str, file_path: str) -> Tuple[bool, str]:
        """Create template files for pattern import"""
        
        try:
            if template_format == 'csv':
                with open(file_path, 'w', encoding='utf-8', newline='') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow(['Component', 'Pattern', 'Description', 'Confidence', 'Category'])
                    writer.writerow(['thunder', 'WPEFramework.*Core::.*crash', 'Thunder core crash', 'high', 'core_crash'])
                    writer.writerow(['hal', 'dsMgrMain.*crash', 'Display manager crash', 'high', 'display_crash'])
                    writer.writerow(['media', 'rmfStreamer.*failed', 'RMF streamer failure', 'medium', 'streaming_error'])
            
            elif template_format == 'json':
                template_data = {
                    "metadata": {
                        "version": "1.0",
                        "description": "Template for pattern import",
                        "created": datetime.now().strftime('%Y-%m-%d'),
                        "format": "import_template"
                    },
                    "patterns": [
                        {
                            "component": "thunder",
                            "pattern": "WPEFramework.*Core::.*crash",
                            "description": "Thunder core crash",
                            "confidence": "high",
                            "category": "core_crash"
                        },
                        {
                            "component": "hal", 
                            "pattern": "dsMgrMain.*crash",
                            "description": "Display manager crash",
                            "confidence": "high",
                            "category": "display_crash"
                        }
                    ]
                }
                
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(template_data, f, indent=2, ensure_ascii=False)
            
            elif template_format == 'txt':
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write("# Pattern Import Template\n")
                    f.write("# Format: Component: Pattern - Description\n")
                    f.write("# or: Pattern | Description | Component\n\n")
                    f.write("thunder: WPEFramework.*Core::.*crash - Thunder core crash\n")
                    f.write("hal: dsMgrMain.*crash - Display manager crash\n")
                    f.write("media: rmfStreamer.*failed - RMF streamer failure\n")
            
            return True, f"Created {template_format} template: {file_path}"
            
        except Exception as e:
            return False, f"Failed to create template: {str(e)}"
