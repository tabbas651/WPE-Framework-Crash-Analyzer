#!/usr/bin/env python3
"""
WPE Framework Crash Analysis Web Application
Phase 1: Crash Discovery & Process Identification
Enhanced with Dynamic Pattern Management & Interactive Chat
"""

from flask import Flask, render_template, request, jsonify, flash, redirect, url_for, send_from_directory
import os
import re
import json
from datetime import datetime
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
import logging

# Import enhanced pattern management systems
from pattern_manager import DynamicPatternManager, ChatPatternInterface
from enhanced_ownership_analyzer import EnhancedOwnershipAnalyzer
from pattern_import_export import PatternImportExport

app = Flask(__name__)
app.secret_key = 'wpe_crash_analysis_secret_key'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB max total upload size

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

class CrashAnalyzer:
    """Phase 1 Crash Discovery and Process Identification"""
    
    def __init__(self):
        self.signal_patterns = {
            'SIGSEGV': r'signal\s+11|SIGSEGV|segmentation\s+fault',
            'SIGABRT': r'signal\s+6|SIGABRT|abort',
            'SIGKILL': r'signal\s+9|SIGKILL|killed',
            'SIGTRAP': r'signal\s+5|SIGTRAP|trap',
            'SIGFPE': r'signal\s+8|SIGFPE|floating\s+point',
            'SIGBUS': r'signal\s+7|SIGBUS|bus\s+error'
        }
        
        self.process_patterns = {
            'wpeframework': r'wpeframework|WPEFramework',
            'thunder': r'thunder|Thunder',
            'plugin': r'plugin|Plugin|lib\w+Plugin',
            'comrpc': r'COMRPC|ComRPC|comrpc'
        }
    
    def extract_device_info(self, log_content, version_file_content=None):
        """Extract MAC address and image version from logs and version.txt"""
        
        # First priority: Look for hostMac= pattern from wpeframework.log
        hostmac_pattern = r'hostMac=([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})'
        hostmac_match = re.search(hostmac_pattern, log_content, re.IGNORECASE)
        
        mac_address = None
        if hostmac_match:
            mac_address = hostmac_match.group(1)
        else:
            # Fallback: Look for other MAC address formats
            mac_pattern = r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})|([0-9A-Fa-f]{12})'
            mac_matches = re.findall(mac_pattern, log_content, re.IGNORECASE)
            
            if mac_matches:
                # Clean up MAC address format
                for match in mac_matches:
                    if match[0] and match[1]:  # Standard MAC format
                        mac_address = f"{match[0]}{match[1]}"
                        break
                    elif match[2]:  # Continuous format
                        mac_address = match[2]
                        break
        
        # Extract image version from version.txt if available
        image_version = None
        if version_file_content:
            # Look for imagename: pattern in version.txt
            imagename_pattern = r'imagename:(.+?)\s*$'
            imagename_match = re.search(imagename_pattern, version_file_content, re.MULTILINE | re.IGNORECASE)
            if imagename_match:
                image_version = imagename_match.group(1).strip()
            else:
                # Fallback to VERSION= pattern
                version_pattern = r'VERSION=(.+?)\s*$'
                version_match = re.search(version_pattern, version_file_content, re.MULTILINE | re.IGNORECASE)
                if version_match:
                    image_version = version_match.group(1).strip()
        
        # If no version.txt, fall back to searching log content
        if not image_version:
            version_pattern = r'version[:\s]+([0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9]*)'
            version_matches = re.findall(version_pattern, log_content, re.IGNORECASE)
            image_version = version_matches[0] if version_matches else None
        
        return mac_address, image_version
    
    def extract_crash_context(self, log_content):
        """Extract additional crash context information"""
        context = {}
        
        # Look for crash upload/telemetry information
        crash_upload_patterns = [
            r'\[CRASH_UPLOAD\].*PID:(\d+)',
            r'Appname.*Process_Crashed\s*=\s*([^,\s]+),\s*([^,\s\]]+)',
            r'Crashed process log file\(s\):\s*([^\s,\]]+)'
        ]
        
        for pattern in crash_upload_patterns:
            matches = re.findall(pattern, log_content, re.IGNORECASE)
            if matches:
                if 'PID:' in pattern:
                    context['crash_pid'] = matches[0]
                elif 'Appname' in pattern:
                    context['app_name'] = matches[0][0]
                    context['crashed_process'] = matches[0][1]
                elif 'log file' in pattern:
                    context['log_files'] = matches[0]
        
        return context
        
    def find_critical_logs_in_directory(self, additional_logs):
        """
        Phase 1 Enhancement: Automatically find core_log.txt and wpeframework.log from directory upload
        Also detects backup/previous logs (bak1_, bak2_, etc.)
        """
        core_log_content = ''
        wpe_log_content = ''
        found_logs = {}
        backup_logs = {'core': {}, 'wpe': {}}
        
        for filename, content in additional_logs.items():
            filename_lower = filename.lower()
            
            # Look for core_log.txt or similar core crash logs
            if ('core_log.txt' in filename_lower or 
                'core.log' in filename_lower or 
                'crash_log' in filename_lower or
                'coredump' in filename_lower):
                
                # Check if it's a backup log
                bak_match = re.search(r'bak(\d+)_', filename_lower)
                if bak_match:
                    backup_number = int(bak_match.group(1))
                    backup_logs['core'][backup_number] = {'filename': filename, 'content': content}
                else:
                    # Current/main log
                    core_log_content = content
                    found_logs['core_log'] = filename
                
            # Look for wpeframework.log or similar Thunder logs  
            elif ('wpeframework.log' in filename_lower or 
                  'wpeframework' in filename_lower or
                  'thunder.log' in filename_lower or
                  'thunder' in filename_lower):
                
                # Check if it's a backup log
                bak_match = re.search(r'bak(\d+)_', filename_lower)
                if bak_match:
                    backup_number = int(bak_match.group(1))
                    backup_logs['wpe'][backup_number] = {'filename': filename, 'content': content}
                else:
                    # Current/main log
                    wpe_log_content = content
                    found_logs['wpe_log'] = filename
        
        # Add backup logs info to found_logs
        found_logs['backup_logs'] = backup_logs
        
        return core_log_content, wpe_log_content, found_logs

    def analyze_backup_logs(self, backup_logs, include_phase2=True, include_phase3=False):
        """
        Analyze backup/previous logs when main logs show no crash
        Returns analysis result from the first backup log containing a genuine crash
        """
        if not backup_logs or (not backup_logs['core'] and not backup_logs['wpe']):
            return None
        
        # Get available backup numbers, prioritizing lower numbers (more recent)
        available_core_backups = sorted(backup_logs['core'].keys()) if backup_logs['core'] else []
        available_wpe_backups = sorted(backup_logs['wpe'].keys()) if backup_logs['wpe'] else []
        
        # Try analyzing each backup pair in order (bak1 first, then bak2, etc.)
        max_backup_to_check = max(
            (max(available_core_backups) if available_core_backups else 0),
            (max(available_wpe_backups) if available_wpe_backups else 0)
        )
        
        for backup_num in range(1, max_backup_to_check + 1):
            # Get backup log contents
            core_backup_content = ''
            wpe_backup_content = ''
            
            if backup_num in backup_logs['core']:
                core_backup_content = backup_logs['core'][backup_num]['content']
            
            if backup_num in backup_logs['wpe']:
                wpe_backup_content = backup_logs['wpe'][backup_num]['content']
            
            if not core_backup_content and not wpe_backup_content:
                continue
                
            # Analyze this backup pair
            backup_result = self.analyze_crash(
                core_backup_content, 
                wpe_backup_content, 
                additional_logs={},  # Backup logs don't have additional logs
                stacktrace_content='',  # No stack trace in backup analysis
                include_phase2=include_phase2,
                include_phase3=include_phase3
            )
            
            # If genuine crash found in backup logs
            if not backup_result.get('no_crash_found', False) and backup_result.get('status') != 'No crash found':
                # Update phase information to indicate this came from backup logs
                backup_filenames = []
                if backup_num in backup_logs['core']:
                    backup_filenames.append(backup_logs['core'][backup_num]['filename'])
                if backup_num in backup_logs['wpe']:
                    backup_filenames.append(backup_logs['wpe'][backup_num]['filename'])
                
                backup_result['phase'] = f"Backup Log Analysis - {backup_result.get('phase', '')} (from {', '.join(backup_filenames)})"
                backup_result['backup_analysis'] = {
                    'backup_number': backup_num,
                    'analyzed_files': backup_filenames,
                    'note': f'Crash found in backup logs bak{backup_num}_ - main logs showed only routine operations'
                }
                
                return backup_result
        
        return None

    def get_backup_log_recommendation(self, backup_logs):
        """
        Generate recommendations for uploading missing backup logs
        """
        recommendations = []
        
        # Check what backup logs are missing
        available_core_backups = sorted(backup_logs['core'].keys()) if backup_logs.get('core') else []
        available_wpe_backups = sorted(backup_logs['wpe'].keys()) if backup_logs.get('wpe') else []
        
        # Suggest uploading backup logs if none are available
        if not available_core_backups and not available_wpe_backups:
            recommendations.append("Please upload the backup/previous log if you need to analyze further.")
        elif not available_core_backups:
            recommendations.append("Please upload the backup/previous log if you need to analyze further.")
        elif not available_wpe_backups:
            recommendations.append("Please upload the backup/previous log if you need to analyze further.")
        
        return recommendations

    def identify_crash_signal(self, log_content):
        """Identify crash signal from log content - balanced detection for genuine crashes"""
        # First check for explicit crash telemetry and crash reporting
        crash_telemetry_patterns = [
            r'Process crashed\s*=\s*([^\s,]+)',  # "Process crashed = WPEFramework"
            r'Appname,\s*Process_Crashed\s*=\s*[^,]+,\s*([^\s,]+)',  # "Appname, Process_Crashed = ..., WPEFramework"
            r'Crashed process log file\(s\):\s*([^\s]+)',  # "Crashed process log file(s): wpeframework.log"
            r'Adding File:.*([^\s]+).*minidump',  # Minidump processing after crash
            r'([^\s]+)\.dmp.*WPEFramework',  # Minidump file with process name
        ]
        
        for pattern in crash_telemetry_patterns:
            matches = re.findall(pattern, log_content, re.IGNORECASE)
            if matches:
                return f'Crash detected: {matches[0]}' if matches[0] else 'Crash detected from telemetry'
        
        # Then check for explicit crash signals with crash context, not routine processing
        genuine_crash_patterns = [
            # Signal crashes with explicit crash context
            (r'(?:crashed|terminated unexpectedly|killed).*signal\s+(\d+)', {
                '11': 'SIGSEGV', '6': 'SIGABRT', '9': 'SIGKILL', 
                '5': 'SIGTRAP', '8': 'SIGFPE', '7': 'SIGBUS',
                '15': 'SIGTERM', '2': 'SIGINT'
            }),
            (r'(?:caught|received)\s+(SIGSEGV|SIGABRT|SIGKILL|SIGTRAP|SIGFPE|SIGBUS)(?!.*processing)', None),
            (r'segmentation\s+fault\s+(?:occurred|at|in)(?!.*processing)', 'SIGSEGV'),
            (r'(?:process|application).*(?:aborted|crashed).*abort', 'SIGABRT'),
            (r'(?:process|application).*killed.*signal', 'SIGKILL'),
            (r'floating\s+point\s+exception\s+(?:in|at)', 'SIGFPE'),
            (r'bus\s+error\s+(?:occurred|at|in)', 'SIGBUS')
        ]
        
        # Exclude routine processing activities
        routine_operations = [
            'starting', 'processing', 'deferring', 'handling', 'cleanup',
            'scheduled', 'routine', 'initializing', 'managing'
        ]
        
        for pattern, mapping in genuine_crash_patterns:
            matches = re.findall(pattern, log_content, re.IGNORECASE)
            if matches:
                # Check if it's not a routine operation
                context_lines = log_content.lower().split('\n')
                for line in context_lines:
                    if any(matches[0].lower() in line for matches in [matches]) and not any(routine in line for routine in routine_operations):
                        if mapping is None:
                            return matches[0].upper()
                        elif isinstance(mapping, dict):
                            signal_num = matches[0]
                            return mapping.get(signal_num, f'Signal {signal_num}')
                        else:
                            return mapping
        
        return 'No crash signal detected'
    
    def identify_crashed_process(self, log_content):
        """Identify crashed process from log content - balanced detection for genuine crashes"""
        # First check for explicit crash telemetry
        crash_telemetry_patterns = [
            r'Process crashed\s*=\s*([^\s,\n]+)',  # "Process crashed = WPEFramework"
            r'Appname,\s*Process_Crashed\s*=\s*[^,]+,\s*([^\s,\n]+)',  # "Appname, Process_Crashed = ..., WPEFramework"
            r'Crashed process log file\(s\):\s*([^\s,\n]+)',  # "Crashed process log file(s): wpeframework.log"
            r'([^\s/]+)\.dmp.*(?:WPEFramework|Thunder|Plugin)',  # Minidump files
        ]
        
        crashed_processes = []
        for pattern in crash_telemetry_patterns:
            matches = re.findall(pattern, log_content, re.IGNORECASE)
            if matches:
                for match in matches:
                    if match and match not in crashed_processes:
                        # Clean up the match (remove .log extension if present)
                        process_name = match.replace('.log', '').strip()
                        crashed_processes.append(process_name)
        
        if crashed_processes:
            return crashed_processes
        
        # Then check for explicit crash processes with definite crash context, not routine processing
        definite_crash_indicators = [
            r'Process\s+crashed\s*[=:]\s*([^\s,\]]+)',
            r'([^\s]+)\s+(?:crashed|terminated unexpectedly|killed by signal)',
            r'CRASH.*Process[:\s]+([^\s,\]]+)',
            r'Crashed\s+process[:\s]+([^\s,\]]+)',
            r'\[CRASH[^\]]*\].*Process[:\s]+([^\s,\]]+)',
            r'Signal.*delivered\s+to\s+(?:crashed\s+)?process[:\s]+([^\s,\]]+)',
            r'(?:Fatal|Critical).*crash.*process[:\s]+([^\s,\]]+)'
        ]
        
        for pattern in definite_crash_indicators:
            matches = re.findall(pattern, log_content, re.IGNORECASE)
            if matches:
                # Verify it's not routine processing
                process_name = matches[0].strip()
                if not self._is_routine_processing(log_content, process_name):
                    return [process_name]
        
        # Look for signal-related crashes with explicit crash context
        signal_crash_patterns = [
            r'([^\s]+)\s+(?:crashed.*signal|terminated.*signal|killed.*signal)',
            r'([^\s]+)\s+segmentation\s+fault\s+(?:occurred|at)',
            r'([^\s]+)\s+(?:fatal|critical).*(?:abort|crashed)'
        ]
        
        for pattern in signal_crash_patterns:
            matches = re.findall(pattern, log_content, re.IGNORECASE)
            if matches:
                process_name = matches[0].strip()
                if not self._is_routine_processing(log_content, process_name):
                    return [process_name]
        
        # Only if we have clear crash context, look for process patterns
        if self._has_definite_crash_context(log_content):
            crash_context_patterns = [
                r'(wpeframework|WPEFramework).*(?:crashed|terminated unexpectedly)',
                r'(thunder|Thunder).*(?:crashed|terminated unexpectedly)',
                r'(plugin|Plugin).*(?:crashed|terminated unexpectedly)'
            ]
            
            for pattern in crash_context_patterns:
                matches = re.findall(pattern, log_content, re.IGNORECASE)
                if matches:
                    return [matches[0].strip()]
        
        return ['No crashed process detected']
    
    def _is_routine_processing(self, log_content, process_name):
        """Check if this is routine processing rather than a crash"""
        routine_keywords = [
            'starting', 'processing', 'deferring', 'cleanup', 'scheduled',
            'handling', 'managing', 'initializing', 'routine', 'maintenance'
        ]
        
        lines = log_content.lower().split('\n')
        for line in lines:
            if process_name.lower() in line:
                if any(keyword in line for keyword in routine_keywords):
                    return True
        return False
    
    def _has_definite_crash_context(self, log_content):
        """Check if log content has definite crash context"""
        # Crash telemetry indicators (highest priority)
        crash_telemetry_indicators = [
            'Process crashed =', 'Crashed process log file(s):', 'Appname, Process_Crashed =',
            '.dmp', 'minidump', 'Adding File:.*minidump'
        ]
        
        # Traditional crash indicators
        definite_crash_indicators = [
            'crashed', 'terminated unexpectedly', 'fatal error', 'segmentation fault at',
            'signal caught', 'unhandled exception', 'core dump generated'
        ]
        
        content_lower = log_content.lower()
        
        # Check for crash telemetry first (these are definite)
        if any(indicator.lower() in content_lower for indicator in crash_telemetry_indicators):
            return True
            
        return any(indicator in content_lower for indicator in definite_crash_indicators)
    
    def extract_crash_timestamp(self, log_content):
        """Extract crash timestamp - prioritizing Signal received patterns from wpeframework.log"""
        # First look for timestamps associated with Signal received (this is the key crash indicator)
        signal_received_patterns = [
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z).*Signal\s+received',
            r'(\d{6}-\d{2}:\d{2}:\d{2}\.\d{3}).*Signal\s+received',
            r'(\d{2}:\d{2}:\d{2}\.\d{3}).*Signal\s+received'
        ]
        
        for pattern in signal_received_patterns:
            matches = re.findall(pattern, log_content, re.IGNORECASE)
            if matches:
                return matches[0]
        
        # Then look for timestamps associated with crash telemetry
        crash_telemetry_patterns = [
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z).*Process crashed\s*=',
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z).*Crashed process log file\(s\):',
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z).*Appname,\s*Process_Crashed\s*=',
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z).*\.dmp.*WPEFramework',
        ]
        
        for pattern in crash_telemetry_patterns:
            matches = re.findall(pattern, log_content, re.IGNORECASE)
            if matches:
                return matches[0]
        
        # Then look for timestamps associated with definite crash events
        definite_crash_timestamp_patterns = [
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z).*(?:[Pp]rocess crashed|crashed|terminated unexpectedly)',
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z).*(?:signal.*(?:11|6|4|8|9)|SIGSEGV|SIGABRT)',
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z).*(?:segmentation fault.*(?:occurred|at)|fatal error)',
            r'(\d{6}-\d{2}:\d{2}:\d{2}\.\d{3}).*(?:[Pp]rocess crashed|crashed|terminated unexpectedly)',
            r'(\d{2}:\d{2}:\d{2}\.\d{3}).*(?:[Pp]rocess crashed|crashed|terminated unexpectedly)'
        ]
        
        for pattern in definite_crash_timestamp_patterns:
            matches = re.findall(pattern, log_content, re.IGNORECASE)
            if matches:
                return matches[0]
        
        # If we have clear crash context but no specific timestamp, look for general patterns
        if (self._has_definite_crash_context(log_content) or 
            'Process crashed =' in log_content or 
            'Crashed process log file(s):' in log_content):
            # Look for any timestamp in crash context
            general_patterns = [
                r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z',
                r'\d{6}-\d{2}:\d{2}:\d{2}\.\d{3}',
                r'\d{2}:\d{2}:\d{2}\.\d{3}'
            ]
            
            for pattern in general_patterns:
                matches = re.findall(pattern, log_content)
                if matches:
                    return matches[-1]  # Return the last timestamp if crash context exists
        
        return 'No crash timestamp detected'
    
    def extract_last_meaningful_logs(self, log_content, context_lines=10):
        """Extract meaningful log entries around Signal received patterns from wpeframework.log"""
        lines = [line.strip() for line in log_content.split('\n') if line.strip()]
        
        # First, look specifically for "Signal received" patterns
        signal_received_indices = []
        for i, line in enumerate(lines):
            if re.search(r'Signal\s+received', line, re.IGNORECASE):
                signal_received_indices.append(i)
        
        # If we found Signal received patterns, extract context around them
        if signal_received_indices:
            meaningful_indices = []
            for signal_idx in signal_received_indices:
                start_idx = max(0, signal_idx - context_lines)
                end_idx = min(len(lines), signal_idx + context_lines + 1)
                meaningful_indices.extend(range(start_idx, end_idx))
            
            # Remove duplicates and sort
            meaningful_indices = sorted(set(meaningful_indices))
            meaningful_logs = [lines[i] for i in meaningful_indices]
            return meaningful_logs[:50]  # Limit to prevent overly long results
        
        # If no Signal received found, fall back to crash telemetry patterns
        crash_telemetry_patterns = [
            r'Process crashed\s*=',
            r'Crashed process log file\(s\):',
            r'Appname,\s*Process_Crashed\s*=',
            r'Adding File:.*minidump',
            r'[^\s]+\.dmp.*WPEFramework',
        ]
        
        # Also look for definite crash patterns (not routine processing)
        definite_crash_patterns = [
            r'(?:WPEFramework|Thunder|wpeframework).*(?:crashed|terminated unexpectedly|killed by signal)(?!.*starting|.*processing)',
            r'(?:process|application).*(?:crashed|terminated unexpectedly|killed by signal)(?!.*starting|.*processing)', 
            r'(?:caught|received)\s+(?:signal\s+(?:11|6|4|8|9)|SIGSEGV|SIGABRT|SIGFPE|SIGBUS)(?!.*processing)',
            r'segmentation\s+fault\s+(?:occurred|at|in)(?!.*processing)',
            r'pure\s+virtual\s+method\s+called(?!.*test)(?!.*processing)',
            r'terminate\s+called(?!.*processing)',
            r'(?:fatal|critical)\s+(?:crash|error)(?!.*processing)(?!.*starting)'
        ]
        
        all_patterns = crash_telemetry_patterns + definite_crash_patterns
        meaningful_indices = []
        
        for i, line in enumerate(lines):
            for pattern in all_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # Add context lines around the crash
                    start_idx = max(0, i - context_lines)
                    end_idx = min(len(lines), i + context_lines + 1)
                    meaningful_indices.extend(range(start_idx, end_idx))
                    break
        
        if meaningful_indices:
            # Remove duplicates and sort
            meaningful_indices = sorted(set(meaningful_indices))
            meaningful_logs = [lines[i] for i in meaningful_indices]
            return meaningful_logs[:50]  # Limit to prevent overly long results
        
        # If no definite crash patterns found, but we have crash telemetry context
        crash_upload_lines = [line for line in lines if 'CRASH_UPLOAD' in line]
        if crash_upload_lines:
            return crash_upload_lines[:20]  # Return crash upload context
        
        return ['No genuine crash events detected - logs show normal system operations']
        
        # Remove the fallback crash keyword search as it was giving false positives

    def analyze_crash(self, core_log_content, wpe_log_content='', additional_logs=None, stacktrace_content='', include_phase2=True, include_phase3=False):
        """Main crash analysis function following Phase 1 design"""
        
        # Extract version.txt content if available in additional_logs
        version_file_content = None
        if additional_logs:
            # Look for version.txt in additional logs
            for filename, content in additional_logs.items():
                if 'version.txt' in filename.lower():
                    version_file_content = content
                    break
        
        # Extract device information from combined content
        combined_content = core_log_content + '\n' + wpe_log_content
        mac_address, image_version = self.extract_device_info(combined_content, version_file_content)
        
        # Phase 1: Check core_log.txt for process crashes first (primary source)
        crashed_processes = self.identify_crashed_process(core_log_content)
        
        # If no crash found in core_log.txt, return "No Crash Detected"
        if crashed_processes == ['No crashed process detected']:
            # Before returning "no crash found", check backup logs if available
            if additional_logs:
                _, _, found_logs = self.find_critical_logs_in_directory(additional_logs)
                backup_logs = found_logs.get('backup_logs', {'core': {}, 'wpe': {}})
                
                backup_result = self.analyze_backup_logs(backup_logs, include_phase2, include_phase3)
                if backup_result:
                    return backup_result
                    
                backup_recommendations = self.get_backup_log_recommendation(backup_logs)
                additional_message = f" {' '.join(backup_recommendations)}" if backup_recommendations else ""
            else:
                additional_message = ""
            
            return {
                'device_info': {
                    'mac_address': mac_address or 'Not found',
                    'image_version': image_version or 'Not found'
                },
                'crash_details': {
                    'crashed_process': ['No crash detected'],
                    'signal': 'No crash signal found',
                    'timestamp': 'N/A',
                    'last_meaningful_logs': ['No crash detected in core_log.txt'],
                    'crash_context': {}
                },
                'ownership_analysis': {
                    'primary_ownership': 'No Crash Detected',
                    'component_category': 'no_crash',
                    'confidence': 'N/A',
                    'hypothesis': 'No crash detected in core_log.txt - Phase 1 analysis complete',
                    'escalation_team': 'None - No crash to analyze',
                    'evidence_summary': [],
                    'detailed_evidence': {},
                    'recommendation': f'No crash detected in core_log.txt. Phase 1 analysis found no process crashes.{additional_message}',
                    'scoring_details': [],
                    'analysis_note': 'Phase 1 design: Check core_log.txt first for process crashes.',
                    'pattern_source': 'Phase 1 crash detection'
                },
                'phase': 'Phase 1 - Crash Discovery & Process Identification',
                'status': 'No crash found',
                'confidence': 'N/A - No crash to analyze',
                'no_crash_found': True,
                'message': 'Phase 1 Complete: No process crash detected in core_log.txt. Please upload the backup/previous log if you need to analyze further.'
            }
        
        # Crash found in core_log.txt - proceed with Phase 1 analysis
        # Get crash signal and timestamp from combined content
        crash_signal = self.identify_crash_signal(combined_content)
        crash_timestamp = self.extract_crash_timestamp(combined_content)
        
        # Get crash context (±10 lines around Signal received) from wpeframework.log
        crash_context_logs = self.extract_last_meaningful_logs(wpe_log_content if wpe_log_content else combined_content, context_lines=10)
        
        # Extract crash context information
        crash_context = self.extract_crash_context(combined_content)
        
        # Phase 1 Results
        analysis_result = {
            'device_info': {
                'mac_address': mac_address or 'Not found',
                'image_version': image_version or 'Not found'
            },
            'crash_details': {
                'crashed_process': crashed_processes,
                'signal': crash_signal,
                'timestamp': crash_timestamp,
                'last_meaningful_logs': crash_context_logs,
                'crash_context': crash_context
            },
            'phase': 'Phase 1 - Crash Discovery & Process Identification',
            'status': 'Crash detected',
            'confidence': self._calculate_confidence(crash_signal, crashed_processes, mac_address, image_version)
        }
        
        # Enhanced Phase 2: Multi-Log Ownership Analysis (if enabled)
        if include_phase2:
            # Use enhanced analyzer with dynamic pattern support
            if additional_logs:
                # Enhanced analysis with multiple logs and all RDK components
                log_files_content = {
                    'core_log.txt': core_log_content,
                    'wpe_log.txt': wpe_log_content
                }
                log_files_content.update(additional_logs)
                
                ownership_result = enhanced_ownership_analyzer.analyze_ownership_with_multi_logs(crash_context, log_files_content)
                analysis_result['phase'] = 'Phase 1 & 2 - Crash Discovery with Multi-Log Ownership Analysis'
            else:
                # Standard single-log analysis with enhanced patterns
                combined_content = core_log_content + '\n' + wpe_log_content
                ownership_result = enhanced_ownership_analyzer.analyze_ownership(crash_context, combined_content)
                analysis_result['phase'] = 'Phase 1 & 2 - Crash Discovery with Ownership Analysis'
            
            analysis_result['ownership_analysis'] = ownership_result
            
            # Ensure ownership_result is properly structured
            if not isinstance(ownership_result, dict) or 'confidence' not in ownership_result:
                # Create a default ownership result structure if needed
                ownership_result = {
                    'primary_ownership': 'Unknown Component',
                    'confidence': 'Low',
                    'hypothesis': 'Unable to determine ownership from available logs',
                    'escalation_team': 'Further investigation required',
                    'evidence_summary': [],
                    'detailed_evidence': {},
                    'recommendation': 'Further investigation recommended',
                    'analysis_note': 'Standard ownership analysis structure applied'
                }
            
            # Update overall confidence based on ownership confidence
            if ownership_result.get('confidence') == 'High':
                analysis_result['overall_confidence'] = 'High'
            elif ownership_result.get('confidence') == 'Medium' and analysis_result['confidence'] in ['Medium', 'High']:
                analysis_result['overall_confidence'] = 'Medium'
            else:
                analysis_result['overall_confidence'] = 'Low'
        
        # Phase 3: Stack Trace Analysis for Confirmed Ownership (if enabled)
        if include_phase3 and stacktrace_content:
            stacktrace_analyzer = StackTraceAnalyzer()
            stacktrace_result = stacktrace_analyzer.analyze_stack_trace(stacktrace_content, core_log_content)
            
            analysis_result['stacktrace_analysis'] = stacktrace_result
            analysis_result['phase'] = 'Phase 1, 2 & 3 Complete - Confirmed Ownership via Stack Trace Analysis'
            
            # Update ownership determination based on Phase 3 analysis
            if stacktrace_result['mac_validation']['consistent']:
                confirmed_ownership = stacktrace_result['confirmed_ownership']
                
                # Override Phase 2 hypothesis with Phase 3 confirmed ownership
                if 'ownership_analysis' in analysis_result and isinstance(analysis_result['ownership_analysis'], dict):
                    analysis_result['ownership_analysis']['phase3_override'] = {
                        'phase2_hypothesis': analysis_result['ownership_analysis'].get('primary_ownership', 'Unknown'),
                        'phase3_confirmed': confirmed_ownership['confirmed_ownership'],
                        'confidence_upgrade': f"Upgraded from {analysis_result['ownership_analysis'].get('confidence', 'Unknown')} to {confirmed_ownership['confidence_level']}"
                    }
                    
                    # Update to confirmed ownership
                    analysis_result['ownership_analysis']['primary_ownership'] = confirmed_ownership['confirmed_ownership']
                    analysis_result['ownership_analysis']['confidence'] = confirmed_ownership['confidence_level']
                    analysis_result['ownership_analysis']['hypothesis'] = f"CONFIRMED: {confirmed_ownership['confirmed_ownership']} ownership based on stack trace analysis. {' | '.join(confirmed_ownership['reasoning'])}"
                
                # Set overall confidence based on Phase 3 results
                analysis_result['overall_confidence'] = confirmed_ownership['confidence_level']
                analysis_result['final_determination'] = 'Confirmed via Stack Trace Analysis'
            else:
                # MAC validation failed
                analysis_result['stacktrace_analysis']['validation_warning'] = 'MAC address inconsistency detected between core logs and stack trace'
                if 'ownership_analysis' in analysis_result and isinstance(analysis_result['ownership_analysis'], dict):
                    analysis_result['ownership_analysis']['confidence'] = 'Low'
                analysis_result['overall_confidence'] = 'Low'
                analysis_result['final_determination'] = 'Inconclusive due to MAC validation failure'
        
        return analysis_result
    
    def _calculate_confidence(self, crash_signal, crashed_processes, mac_address, image_version):
        """Calculate confidence level based on available evidence"""
        confidence_factors = 0
        
        if crash_signal and any(keyword in crash_signal.lower() for keyword in [
            'crashed', 'segfault', 'abort', 'fatal', 'exception', 'signal', 'dump'
        ]):
            confidence_factors += 2
        
        if crashed_processes:
            confidence_factors += 2
        
        if mac_address and mac_address != 'Not found':
            confidence_factors += 1
        
        if image_version and image_version != 'Not found':
            confidence_factors += 1
        
        if confidence_factors >= 4:
            return 'High'
        elif confidence_factors >= 2:
            return 'Medium'
        else:
            return 'Low'
    
    def _calculate_confidence(self, signal, processes, mac, version):
        """Calculate confidence level based on extracted information"""
        # Handle no crash detected scenarios
        if (signal == 'No crash signal detected' or 
            processes == ['No crashed process detected'] or
            'No genuine crash events detected' in str(processes)):
            return 'N/A - No crash detected'
        
        # Traditional confidence calculation for genuine crashes  
        if signal != 'Unknown' and processes != ['Unknown'] and 'Unknown' not in processes:
            return 'High'
        elif signal != 'Unknown' or (processes != ['Unknown'] and 'Unknown' not in processes):
            return 'Medium'
        else:
            return 'Low'


class StackTraceAnalyzer:
    """Phase 3 Stack Trace Analysis for Confirmed Ownership Determination"""
    
    def __init__(self):
        # Enhanced framework vs Plugin code patterns for accurate symbol resolution
        self.framework_symbols = {
            'thunder_core': [
                # WPEFramework core patterns
                r'WPEFramework::(?:Core|Plugin)::[\w:]+',
                r'Thunder::(?:Core|Plugin|Framework)::[\w:]+',
                r'Core::(?:WorkerPool|MessageDispatcher|Library|ServiceAdministrator)::[\w:]+',
                r'WPEFramework::(?:PluginHost|Framework|Service)::[\w:]+',
                # Framework lifecycle patterns  
                r'Plugin::(?:Initialize|Deinitialize|Activate|Deactivate)\(',
                r'IPlugin::(?:Initialize|Deinitialize|Activate|Deactivate)',
                # Core framework files
                r'.*WPEFramework.*\.(?:cpp|h)\b',
                r'.*Thunder.*\.(?:cpp|h)\b',
                r'.*Core.*\.(?:cpp|h)\b'
            ],
            'thunder_plugin': [
                # Plugin-specific patterns
                r'\w+Plugin::(?!Initialize|Deinitialize)[\w:]+',
                r'lib\w+Plugin\.so',
                r'org\.rdk\.[\w\.]*Plugin[\w]*',
                # Specific plugin implementations
                r'(?:Netflix|YouTube|Cobalt|WebKit|Lightning|Resident)::[\w:]+',
                r'(?:DisplaySettings|UserSettings|DeviceSettings)::[\w:]+',
                r'(?:Network|Wifi|Bluetooth|LocationSync)::[\w:]+',
                # Plugin files
                r'.*Plugin.*\.(?:cpp|h|so)\b',
                r'.*(?:Netflix|YouTube|Cobalt).*\.(?:cpp|h|so)\b'
            ],
            'comrpc_layer': [
                # COMRPC and RPC patterns
                r'COMRPC::(?:Invoke|Administrator|Engine)::[\w:]+',
                r'RPC::(?:Server|Client|Connection)::[\w:]+',
                r'ProxyStub::[\w:]+',
                r'.*COMRPC.*\.(?:cpp|h)\b',
                r'.*RPC.*\.(?:cpp|h)\b'
            ],
            'webkit_engine': [
                # WebKit/Browser engine patterns (often plugin responsibility)
                r'WebCore::[\w:]+',
                r'WebKit::[\w:]+',
                r'WTF::[\w:]+',
                r'JSC::[\w:]+',
                r'.*WebKit.*\.(?:cpp|h|so)\b'
            ]
        }
        
        # Critical framework boundary functions
        self.boundary_functions = [
            'Initialize', 'Deinitialize', 'Activate', 'Deactivate',
            'QueryInterface', 'AddRef', 'Release'
        ]
    
    def analyze_stack_trace(self, stacktrace_content, core_log_content):
        """Analyze stack trace for definitive ownership determination"""
        # Validate MAC address consistency
        mac_validation = self._validate_mac_consistency(stacktrace_content, core_log_content)
        
        # Parse call stack
        call_stack = self._parse_call_stack(stacktrace_content)
        
        # Analyze crash location
        crash_location = self._analyze_crash_location(stacktrace_content, call_stack)
        
        # Analyze thread information
        thread_analysis = self._analyze_thread_info(stacktrace_content)
        
        # Perform symbol resolution for ownership determination
        ownership_analysis = self._resolve_ownership_from_symbols(call_stack, crash_location)
        
        # Determine confirmed ownership with high confidence
        confirmed_ownership = self._determine_confirmed_ownership(ownership_analysis, crash_location)
        
        return {
            'mac_validation': mac_validation,
            'call_stack_analysis': call_stack,
            'crash_location': crash_location,
            'thread_analysis': thread_analysis,
            'symbol_resolution': ownership_analysis,
            'confirmed_ownership': confirmed_ownership,
            'phase3_confidence': 'High' if mac_validation['consistent'] and call_stack else 'Medium'
        }
    
    def _validate_mac_consistency(self, stacktrace_content, core_log_content):
        """Validate MAC address consistency between stack trace and core logs"""
        # Extract MAC from stack trace dump file name or content
        stacktrace_mac_patterns = [
            r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})',
            r'([0-9A-Fa-f]{12})',
            r'MAC[:\s]+([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})'
        ]
        
        stacktrace_macs = []
        for pattern in stacktrace_mac_patterns:
            matches = re.findall(pattern, stacktrace_content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple) and len(match) >= 2:
                    mac = f"{match[0]}{match[1]}".replace(':', '').replace('-', '')
                else:
                    mac = match.replace(':', '').replace('-', '')
                stacktrace_macs.append(mac.upper())
        
        # Extract MAC from core logs
        core_mac_patterns = [
            r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})',
            r'([0-9A-Fa-f]{12})'
        ]
        
        core_macs = []
        for pattern in core_mac_patterns:
            matches = re.findall(pattern, core_log_content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple) and len(match) >= 2:
                    mac = f"{match[0]}{match[1]}".replace(':', '').replace('-', '')
                else:
                    mac = match.replace(':', '').replace('-', '')
                core_macs.append(mac.upper())
        
        # Check consistency
        consistent = bool(stacktrace_macs and core_macs and 
                         any(st_mac in core_macs for st_mac in stacktrace_macs))
        
        return {
            'consistent': consistent,
            'stacktrace_macs': list(set(stacktrace_macs)),
            'core_log_macs': list(set(core_macs)),
            'validation_status': 'PASS' if consistent else 'FAIL'
        }
    
    def _parse_call_stack(self, stacktrace_content):
        """Parse call stack to extract function call chain with enhanced accuracy"""
        call_stack = []
        
        # Enhanced stack trace patterns for different formats and tools
        stack_patterns = [
            # GDB style: #0  0x7ffff7a05428 in function_name () at file.cpp:123
            r'#(\d+)\s+0x([0-9a-fA-F]+)\s+in\s+([^\s\(]+)\s*\([^)]*\)\s*(?:at\s+([^:]+):(\d+))?',
            # GDB with module: #0  0x7ffff7a05428 in func() from /lib/module.so
            r'#(\d+)\s+0x([0-9a-fA-F]+)\s+in\s+([^\s\(]+)\s*\([^)]*\)\s*from\s+([^\s]+)',
            # Valgrind style: ==123== at 0x123456: function_name (file.cpp:123)
            r'==\d+==\s+at\s+0x([0-9a-fA-F]+):\s+([^\s\(]+)\s*\([^)]*\)\s*\(([^:]+):(\d+)\)',
            # Simple format: function_name() [file.cpp:123]
            r'([\w:~<>]+)\([^)]*\)\s*\[([^:]+):(\d+)\]',
            # Crashpad/Breakpad: 0 module.so 0x12345 function_name [file.cpp:123]
            r'(\d+)\s+([^\s]+)\s+0x([0-9a-fA-F]+)\s+([^\s\[]+)\s*\[([^:]+):(\d+)\]',
            # Address with symbol: 0x12345678 <function_name+0x45>
            r'0x([0-9a-fA-F]+)\s+<([^+>]+)(?:\+0x[0-9a-fA-F]+)?>',
            # Stack frame with module: func_name+0x123 in module.so
            r'([^+\s]+)\+0x([0-9a-fA-F]+)\s+in\s+([^\s]+)',
            # Android/ARM format: pc 0x12345678  /system/lib/module.so (function_name)
            r'pc\s+0x([0-9a-fA-F]+)\s+([^\s]+)\s*\(([^)]+)\)',
            # Minimal format: function_name file.cpp:123
            r'^\s*([\w:~<>]+)\s+([^:]+):(\d+)\s*$'
        ]
        
        lines = stacktrace_content.split('\n')
        frame_counter = 0
        
        for line_idx, line in enumerate(lines):
            line = line.strip()
            if not line or line.startswith('Thread') or line.startswith('=='):
                continue
            
            # Try each pattern in order of specificity
            for pattern_idx, pattern in enumerate(stack_patterns):
                match = re.search(pattern, line)
                if match:
                    groups = match.groups()
                    
                    # Parse based on pattern type
                    frame_info = self._parse_stack_frame(pattern_idx, groups, frame_counter, line)
                    if frame_info:
                        call_stack.append(frame_info)
                        frame_counter += 1
                    break
        
        return sorted(call_stack, key=lambda x: x['frame'])
    
    def _parse_stack_frame(self, pattern_idx, groups, frame_counter, raw_line):
        """Parse individual stack frame based on pattern type"""
        frame_info = {
            'frame': frame_counter,
            'address': 'unknown',
            'function': 'unknown',
            'source_file': 'unknown', 
            'line_number': 'unknown',
            'module': 'unknown',
            'raw_line': raw_line
        }
        
        try:
            if pattern_idx == 0:  # GDB style with optional source location
                frame_info['frame'] = int(groups[0])
                frame_info['address'] = groups[1]
                frame_info['function'] = groups[2]
                if len(groups) > 3 and groups[3]:  # Source file present
                    frame_info['source_file'] = groups[3]
                    frame_info['line_number'] = groups[4] if len(groups) > 4 else 'unknown'
                    
            elif pattern_idx == 1:  # GDB with module
                frame_info['frame'] = int(groups[0])
                frame_info['address'] = groups[1]
                frame_info['function'] = groups[2]
                frame_info['module'] = groups[3]
                
            elif pattern_idx == 2:  # Valgrind style
                frame_info['address'] = groups[0]
                frame_info['function'] = groups[1]
                frame_info['source_file'] = groups[2]
                frame_info['line_number'] = groups[3]
                
            elif pattern_idx == 3:  # Simple format
                frame_info['function'] = groups[0]
                frame_info['source_file'] = groups[1]
                frame_info['line_number'] = groups[2]
                
            elif pattern_idx == 4:  # Crashpad/Breakpad
                frame_info['frame'] = int(groups[0])
                frame_info['module'] = groups[1]
                frame_info['address'] = groups[2]
                frame_info['function'] = groups[3]
                frame_info['source_file'] = groups[4]
                frame_info['line_number'] = groups[5]
                
            elif pattern_idx == 5:  # Address with symbol
                frame_info['address'] = groups[0]
                frame_info['function'] = groups[1]
                
            elif pattern_idx == 6:  # Stack frame with module
                frame_info['function'] = groups[0]
                frame_info['address'] = groups[1]
                frame_info['module'] = groups[2]
                
            elif pattern_idx == 7:  # Android/ARM format
                frame_info['address'] = groups[0]
                frame_info['module'] = groups[1]
                frame_info['function'] = groups[2]
                
            elif pattern_idx == 8:  # Minimal format
                frame_info['function'] = groups[0]
                frame_info['source_file'] = groups[1]
                frame_info['line_number'] = groups[2]
                
            return frame_info
            
        except (ValueError, IndexError) as e:
            # If parsing fails, return basic info
            frame_info['frame'] = frame_counter
            return frame_info
        
        return sorted(call_stack, key=lambda x: x['frame'])
    
    def _analyze_crash_location(self, stacktrace_content, call_stack):
        """Analyze exact crash location from stack trace"""
        crash_location = {
            'crash_function': 'Unknown',
            'source_file': 'Unknown',
            'line_number': 'Unknown',
            'assembly_address': 'Unknown',
            'crash_context': []
        }
        
        if call_stack:
            # The top frame (frame 0) is usually the crash location
            top_frame = call_stack[0]
            crash_location.update({
                'crash_function': top_frame['function'],
                'source_file': top_frame['source_file'],
                'line_number': top_frame['line_number'],
                'assembly_address': top_frame['address']
            })
        
        # Extract context around crash
        crash_context_patterns = [
            r'signal\s+\d+.*received',
            r'segmentation\s+fault',
            r'pure\s+virtual\s+method\s+called',
            r'terminate\s+called'
        ]
        
        lines = stacktrace_content.split('\n')
        for i, line in enumerate(lines):
            for pattern in crash_context_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # Get context lines around the crash
                    start = max(0, i - 2)
                    end = min(len(lines), i + 3)
                    crash_location['crash_context'] = lines[start:end]
                    break
        
        return crash_location
    
    def _analyze_thread_info(self, stacktrace_content):
        """Enhanced thread analysis with comprehensive pattern recognition"""
        thread_info = {
            'thread_id': 'Unknown',
            'thread_type': 'Unknown',
            'thread_state': 'Unknown',
            'thread_name': 'Unknown',
            'multiple_threads': False,
            'thread_details': [],
            'crash_thread_info': {}
        }
        
        # Enhanced thread identification patterns
        thread_patterns = [
            # Linux/GDB patterns
            r'Thread\s+(\d+)\s+\(LWP\s+(\d+)\)\s*"?([^"\n]*)"?',
            r'Thread\s+(\d+)\s+\(([^)]+)\)',
            r'LWP\s+(\d+)',
            # Thread ID patterns
            r'TID[:\s]+(\d+)',
            r'thread\s+id[:\s]+(\d+)',
            r'Thread[:\s]+(\d+)',
            # Thread name patterns
            r'"([^"]+)"\s+.*thread',
            r'thread\s+name[:\s]+"?([^"\n\s]+)"?',
            # Thread state patterns
            r'Thread.*\((RUNNING|STOPPED|BLOCKED|WAITING|SLEEPING)\)',
            r'State[:\s]+(\w+)',
            # Process/Thread info
            r'Process[:\s]+(\d+),?\s*Thread[:\s]+(\d+)',
            # Android/Native patterns
            r'pid:\s*(\d+),?\s*tid:\s*(\d+)',
            # Core dump patterns
            r'Core was generated by.*thread\s+(\d+)'
        ]
        
        lines = stacktrace_content.split('\n')
        thread_count = 0
        main_thread_found = False
        
        for line_idx, line in enumerate(lines):
            line = line.strip()
            
            for pattern in thread_patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    groups = match.groups()
                    
                    # Extract thread information based on pattern
                    thread_detail = self._extract_thread_detail(pattern, groups, line)
                    
                    if thread_detail and thread_detail not in thread_info['thread_details']:
                        thread_info['thread_details'].append(thread_detail)
                        thread_count += 1
                        
                        # Set main thread info (first thread or explicitly main)
                        if (thread_count == 1 or 
                            'main' in thread_detail.get('name', '').lower() or
                            thread_detail.get('id') == '1'):
                            
                            if not main_thread_found:
                                thread_info['thread_id'] = thread_detail.get('id', 'Unknown')
                                thread_info['thread_name'] = thread_detail.get('name', 'Unknown')
                                thread_info['thread_type'] = self._classify_thread_type(thread_detail.get('name', ''))
                                thread_info['thread_state'] = thread_detail.get('state', 'Unknown')
                                main_thread_found = True
                    break
        
        # Enhanced crash thread analysis
        crash_thread = self._identify_crash_thread(stacktrace_content, thread_info['thread_details'])
        if crash_thread:
            thread_info['crash_thread_info'] = crash_thread
            # Override main thread info if crash thread is different
            if crash_thread.get('id') != thread_info['thread_id']:
                thread_info['thread_id'] = crash_thread.get('id', thread_info['thread_id'])
                thread_info['thread_type'] = self._classify_thread_type(crash_thread.get('name', ''))
                thread_info['thread_state'] = crash_thread.get('state', thread_info['thread_state'])
        
        thread_info['multiple_threads'] = thread_count > 1
        
        return thread_info
    
    def _extract_thread_detail(self, pattern, groups, line):
        """Extract thread details based on the matched pattern"""
        detail = {}
        
        try:
            if 'LWP' in pattern and 'Thread' in pattern:
                detail['id'] = groups[0]
                detail['lwp'] = groups[1]
                detail['name'] = groups[2] if len(groups) > 2 else 'unknown'
            elif 'Thread' in pattern and len(groups) >= 2:
                detail['id'] = groups[0]
                detail['name'] = groups[1]
            elif 'TID' in pattern or 'thread id' in pattern.lower():
                detail['id'] = groups[0]
                detail['name'] = 'unknown'
            elif 'thread name' in pattern.lower():
                detail['name'] = groups[0]
            elif 'RUNNING|STOPPED' in pattern:
                detail['state'] = groups[0]
            elif 'Process' in pattern and 'Thread' in pattern:
                detail['process_id'] = groups[0]
                detail['id'] = groups[1]
            elif 'pid:' in pattern.lower():
                detail['process_id'] = groups[0]
                detail['id'] = groups[1]
            
            return detail if detail else None
            
        except (IndexError, ValueError):
            return None
    
    def _identify_crash_thread(self, stacktrace_content, thread_details):
        """Identify the specific thread that crashed"""
        crash_indicators = [
            r'Thread\s+(\d+).*received signal',
            r'Thread\s+(\d+).*crashed',
            r'Fatal signal.*thread\s+(\d+)',
            r'Crashed thread[:\s]+(\d+)',
            r'Thread\s+(\d+).*fault',
            r'#0.*in thread\s+(\d+)'
        ]
        
        for indicator in crash_indicators:
            match = re.search(indicator, stacktrace_content, re.IGNORECASE)
            if match:
                crashed_thread_id = match.group(1)
                
                # Find the thread detail for this ID
                for thread_detail in thread_details:
                    if thread_detail.get('id') == crashed_thread_id:
                        thread_detail['crashed'] = True
                        return thread_detail
                
                # If not found in details, create basic info
                return {
                    'id': crashed_thread_id,
                    'name': 'unknown',
                    'state': 'crashed',
                    'crashed': True
                }
        
        return None
    
    def _classify_thread_type(self, thread_name):
        """Enhanced thread classification with comprehensive pattern matching"""
        if not thread_name or thread_name == 'unknown':
            return 'Unknown Thread'
        
        thread_name_lower = thread_name.lower()
        
        # Main thread patterns
        if any(pattern in thread_name_lower for pattern in ['main', 'primary', 'ui', 'render']):
            return 'Main Thread'
        
        # Worker thread patterns
        elif any(pattern in thread_name_lower for pattern in ['worker', 'background', 'task', 'job']):
            return 'Worker Thread'
        
        # Plugin-specific thread patterns
        elif any(pattern in thread_name_lower for pattern in ['plugin', 'netflix', 'youtube', 'cobalt', 'webkit']):
            return 'Plugin Thread'
        
        # RPC/Communication thread patterns
        elif any(pattern in thread_name_lower for pattern in ['rpc', 'comrpc', 'ipc', 'dbus', 'message']):
            return 'RPC Thread'
        
        # Network thread patterns
        elif any(pattern in thread_name_lower for pattern in ['network', 'socket', 'http', 'curl']):
            return 'Network Thread'
        
        # Media/Decoder thread patterns
        elif any(pattern in thread_name_lower for pattern in ['media', 'video', 'audio', 'decode', 'playback']):
            return 'Media Thread'
        
        # Timer/Event thread patterns
        elif any(pattern in thread_name_lower for pattern in ['timer', 'event', 'signal', 'dispatch']):
            return 'Event Thread'
        
        # IO thread patterns
        elif any(pattern in thread_name_lower for pattern in ['io', 'file', 'disk', 'storage']):
            return 'IO Thread'
        
        # Thread pool patterns
        elif any(pattern in thread_name_lower for pattern in ['pool', 'executor']):
            return 'Thread Pool Worker'
        
        # If thread name contains numbers, likely a generic worker
        elif re.search(r'thread[\s-]*\d+', thread_name_lower):
            return 'Worker Thread'
        
        else:
            return f'Custom Thread ({thread_name})'
    
    def _resolve_ownership_from_symbols(self, call_stack, crash_location):
        """Enhanced symbol resolution with comprehensive ownership analysis"""
        ownership_evidence = {
            'thunder_core_symbols': [],
            'thunder_plugin_symbols': [],
            'comrpc_symbols': [],
            'webkit_engine_symbols': [],
            'boundary_crossings': [],
            'crash_origin_ownership': 'Unknown',
            'ownership_confidence_scores': {'thunder_core': 0, 'thunder_plugin': 0, 'comrpc_layer': 0, 'webkit_engine': 0}
        }
        
        # Analyze each frame in the call stack with weighted scoring
        for frame in call_stack:
            function_name = frame['function']
            source_file = frame['source_file']
            module = frame.get('module', '')
            
            # Combine all identifiable information
            frame_context = f"{function_name} {source_file} {module}"
            
            # Check against framework symbols with confidence scoring
            for category, patterns in self.framework_symbols.items():
                category_score = 0
                matched_patterns = []
                
                for pattern in patterns:
                    # Check function name, source file, and module
                    function_match = re.search(pattern, function_name, re.IGNORECASE)
                    source_match = re.search(pattern, source_file, re.IGNORECASE)
                    module_match = re.search(pattern, module, re.IGNORECASE)
                    
                    if function_match or source_match or module_match:
                        # Score based on match quality and frame position
                        match_score = self._calculate_symbol_match_score(frame['frame'], pattern, function_match, source_match, module_match)
                        category_score += match_score
                        matched_patterns.append(pattern)
                
                if category_score > 0:
                    evidence = {
                        'frame': frame['frame'],
                        'function': function_name,
                        'source_file': source_file,
                        'module': module,
                        'patterns_matched': matched_patterns,
                        'confidence_score': category_score
                    }
                    
                    ownership_evidence['ownership_confidence_scores'][category] += category_score
                    
                    if category == 'thunder_core':
                        ownership_evidence['thunder_core_symbols'].append(evidence)
                    elif category == 'thunder_plugin':
                        ownership_evidence['thunder_plugin_symbols'].append(evidence)
                    elif category == 'comrpc_layer':
                        ownership_evidence['comrpc_symbols'].append(evidence)
                    elif category == 'webkit_engine':
                        ownership_evidence['webkit_engine_symbols'].append(evidence)
        
        # Enhanced boundary crossing analysis
        for i in range(len(call_stack) - 1):
            current_frame = call_stack[i]
            next_frame = call_stack[i + 1]
            
            current_ownership = self._determine_frame_ownership(
                current_frame['function'], 
                current_frame['source_file'], 
                current_frame.get('module', '')
            )
            next_ownership = self._determine_frame_ownership(
                next_frame['function'], 
                next_frame['source_file'], 
                next_frame.get('module', '')
            )
            
            if (current_ownership != next_ownership and 
                current_ownership != 'Unknown' and 
                next_ownership != 'Unknown'):
                
                boundary_info = {
                    'from_frame': next_frame['frame'],
                    'to_frame': current_frame['frame'],
                    'from_ownership': next_ownership,
                    'to_ownership': current_ownership,
                    'boundary_function': current_frame['function'],
                    'transition_type': f"{next_ownership} → {current_ownership}"
                }
                ownership_evidence['boundary_crossings'].append(boundary_info)
        
        # Determine crash origin ownership based on top frame with enhanced analysis
        if call_stack:
            top_frame = call_stack[0]
            top_frame_ownership = self._determine_frame_ownership(
                top_frame['function'],
                top_frame['source_file'], 
                top_frame.get('module', '')
            )
            ownership_evidence['crash_origin_ownership'] = top_frame_ownership
        
        return ownership_evidence
    
    def _calculate_symbol_match_score(self, frame_num, pattern, function_match, source_match, module_match):
        """Calculate weighted score for symbol matches"""
        base_score = 1.0
        
        # Higher weight for earlier frames (closer to crash)
        frame_weight = max(0.1, 1.0 - (frame_num * 0.1))
        
        # Higher weight for function name matches
        match_weight = 0
        if function_match:
            match_weight += 3.0
        if source_match:
            match_weight += 2.0
        if module_match:
            match_weight += 1.5
        
        # Higher weight for specific patterns (framework vs generic)
        pattern_weight = 2.0 if ('::' in pattern or 'Plugin' in pattern) else 1.0
        
        return base_score * frame_weight * match_weight * pattern_weight
    
    def _determine_frame_ownership(self, function_name, source_file='', module=''):
        """Enhanced frame ownership determination with multiple context clues"""
        # Combine all available information
        frame_context = f"{function_name} {source_file} {module}"
        
        best_match = {'category': 'Unknown', 'score': 0}
        
        for category, patterns in self.framework_symbols.items():
            for pattern in patterns:
                if re.search(pattern, frame_context, re.IGNORECASE):
                    # Simple scoring for single frame analysis
                    score = 1.0
                    if re.search(pattern, function_name, re.IGNORECASE):
                        score += 2.0
                    if re.search(pattern, source_file, re.IGNORECASE):
                        score += 1.0
                    
                    if score > best_match['score']:
                        best_match = {'category': category, 'score': score}
        
        return best_match['category'].replace('_', ' ').title() if best_match['category'] != 'Unknown' else 'Unknown'
    
    def _determine_confirmed_ownership(self, ownership_analysis, crash_location):
        """Enhanced ownership determination with sophisticated confidence analysis"""
        # Get confidence scores and symbol counts
        confidence_scores = ownership_analysis['ownership_confidence_scores']
        thunder_core_count = len(ownership_analysis['thunder_core_symbols'])
        thunder_plugin_count = len(ownership_analysis['thunder_plugin_symbols'])
        comrpc_count = len(ownership_analysis['comrpc_symbols'])
        webkit_count = len(ownership_analysis['webkit_engine_symbols'])
        
        crash_origin = ownership_analysis['crash_origin_ownership']
        boundary_crossings = ownership_analysis['boundary_crossings']
        
        # Determine ownership based on weighted confidence scores
        max_score = max(confidence_scores.values()) if confidence_scores.values() else 0
        winning_category = max(confidence_scores, key=confidence_scores.get) if max_score > 0 else 'unknown'
        
        # Confidence calculation based on score distribution
        confidence = 'Medium'  # Start with Medium for Phase 3
        reasoning = []
        ownership = 'Unknown'
        
        # High confidence criteria
        if max_score >= 15.0 and confidence_scores[winning_category] > (sum(confidence_scores.values()) * 0.6):
            confidence = 'High'
        elif max_score >= 8.0 and confidence_scores[winning_category] > (sum(confidence_scores.values()) * 0.5):
            confidence = 'High'
        elif max_score >= 3.0:
            confidence = 'Medium'
        else:
            confidence = 'Low'
        
        # Map category to ownership
        category_map = {
            'thunder_core': 'Thunder Core Framework',
            'thunder_plugin': 'Thunder Plugin',
            'comrpc_layer': 'COMRPC Layer',
            'webkit_engine': 'WebKit Engine (Plugin)',
            'unknown': 'Unknown'
        }
        
        ownership = category_map.get(winning_category, 'Unknown')
        
        # Build detailed reasoning
        if max_score > 0:
            reasoning.append(f'Highest confidence score: {confidence_scores[winning_category]:.1f} for {ownership}')
            
            # Add specific evidence
            if winning_category == 'thunder_core':
                reasoning.append(f'Thunder Core evidence: {thunder_core_count} frames with framework patterns')
                if crash_origin in ['Thunder Core', 'Unknown']:
                    reasoning.append(f'Crash location analysis supports framework ownership: {crash_location["crash_function"]}')
                    
            elif winning_category == 'thunder_plugin':
                reasoning.append(f'Plugin evidence: {thunder_plugin_count} frames with plugin-specific patterns')
                if crash_origin in ['Thunder Plugin', 'Unknown']:
                    reasoning.append(f'Crash location analysis supports plugin ownership: {crash_location["crash_function"]}')
                    
            elif winning_category == 'webkit_engine':
                reasoning.append(f'WebKit/Browser engine evidence: {webkit_count} frames')
                reasoning.append('WebKit engine crashes typically indicate plugin-side issues')
                ownership = 'Thunder Plugin (WebKit Engine)'
                
            elif winning_category == 'comrpc_layer':
                reasoning.append(f'COMRPC evidence: {comrpc_count} frames with communication layer patterns')
                reasoning.append('COMRPC issues may indicate interface boundary problems')
        else:
            reasoning.append('No clear ownership patterns detected in stack trace symbols')
            confidence = 'Low'
        
        # Analyze boundary crossings for additional insights
        if boundary_crossings:
            reasoning.append(f'Detected {len(boundary_crossings)} component boundary crossings')
            
            # Complex boundary analysis
            plugin_to_core = sum(1 for bc in boundary_crossings if 'Plugin' in bc.get('to_ownership', '') and 'Core' in bc.get('from_ownership', ''))
            core_to_plugin = sum(1 for bc in boundary_crossings if 'Core' in bc.get('to_ownership', '') and 'Plugin' in bc.get('from_ownership', ''))
            
            if plugin_to_core > core_to_plugin:
                reasoning.append('More plugin-to-framework calls detected - potential plugin-initiated issue')
            elif core_to_plugin > plugin_to_core:
                reasoning.append('More framework-to-plugin calls detected - potential framework-initiated issue')
        
        # Final ownership determination with crash origin consideration
        if crash_origin != 'Unknown' and crash_origin in category_map.values():
            crash_origin_category = {v: k for k, v in category_map.items()}.get(crash_origin)
            if crash_origin_category and confidence_scores.get(crash_origin_category, 0) > 0:
                # Boost confidence if crash origin aligns with evidence
                if crash_origin_category == winning_category:
                    reasoning.append(f'Crash origin analysis confirms {ownership} ownership')
                    if confidence == 'Medium':
                        confidence = 'High'
                else:
                    reasoning.append(f'Crash origin ({crash_origin}) differs from stack analysis ({ownership})')
                    if confidence == 'High':
                        confidence = 'Medium'
        
        return {
            'confirmed_ownership': ownership,
            'confidence_level': confidence,
            'reasoning': reasoning,
            'evidence_summary': {
                'thunder_core_frames': thunder_core_count,
                'thunder_plugin_frames': thunder_plugin_count,
                'comrpc_frames': comrpc_count,
                'webkit_frames': webkit_count,
                'boundary_crossings': len(boundary_crossings),
                'crash_origin': crash_origin,
                'confidence_scores': confidence_scores
            },
            'phase': 'Phase 3 - Confirmed Ownership via Enhanced Stack Trace Analysis'
        }



class OwnershipAnalyzer:
    """Phase 2 Thunder vs Plugin Responsibility Analysis"""
    
    def __init__(self):
        # Thunder-specific log pattern heuristics for ownership determination
        # More specific patterns for accurate Thunder vs Plugin vs COMRPC distinction
        self.ownership_patterns = {
            'thunder_plugin': [
                # High confidence plugin patterns
                (r'\[([^\]]+Plugin)\].*(?:pure\s+virtual\s+method\s+called|terminate\s+called)', 'specific_plugin_crash', 'high'),
                (r'Activated\s+plugin\s+\[([^\]]+)\].*(?:Signal\s+received|segmentation\s+fault)', 'plugin_activation_crash', 'high'),
                (r'org\.rdk\.\w+Plugin.*(?:pure\s+virtual|terminate\s+called|Signal\s+received)', 'rdk_plugin_crash', 'high'),
                (r'lib\w+Plugin\.so.*(?:crash|abort|signal|fault)', 'plugin_library_crash', 'high'),
                # Medium confidence plugin patterns
                (r'plugin.*Initialize\(\).*(?:failed|crash|abort)', 'plugin_init_failure', 'medium'),
                (r'plugin.*Deinitialize\(\).*(?:failed|crash|abort)', 'plugin_deinit_failure', 'medium'),
                (r'UserSettings.*pure\s+virtual|DisplaySettings.*pure\s+virtual', 'common_plugin_virtual_error', 'medium'),
                # Low confidence plugin patterns
                (r'plugin.*(?:exception|error)', 'plugin_general_error', 'low')
            ],
            'thunder_core': [
                # High confidence Thunder core patterns
                (r'WPEFramework.*Core::.*(?:crash|abort|signal|fault)', 'thunder_core_crash', 'high'),
                (r'Core::WorkerPool.*(?:crash|abort|assert)', 'worker_pool_crash', 'high'),
                (r'Thunder.*Framework.*(?:assert|abort).*core', 'framework_assert_failure', 'high'),
                # Medium confidence Thunder core patterns
                (r'MessageDispatcher.*(?:failure|crash|abort)', 'messaging_failure', 'medium'),
                (r'WPEFramework.*(?:startup|initialization).*failed', 'framework_startup_failure', 'medium'),
                # Low confidence Thunder core patterns
                (r'Thunder.*(?:error|exception)', 'thunder_general_error', 'low')
            ],
            'comrpc_layer': [
                # High confidence COMRPC patterns
                (r'COMRPC::Invoke.*(?:crash|abort|segmentation\s+fault)', 'comrpc_invoke_crash', 'high'),
                (r'COMRPC.*boundary.*(?:violation|crash|error)', 'comrpc_boundary_issue', 'high'),
                # Medium confidence COMRPC patterns
                (r'COMRPC.*(?:timeout|failed|error)', 'comrpc_communication_error', 'medium'),
                (r'RPC.*call.*(?:failed|timeout|crash)', 'rpc_call_failure', 'medium')
            ]
        }
    
    def analyze_ownership_with_multi_logs(self, crash_context, log_files_content):
        """Enhanced ownership analysis using multiple log files and incident detection"""
        # Use enhanced ownership analyzer for multi-log analysis
        enhanced_analyzer = EnhancedOwnershipAnalyzer()
        incident_analysis = enhanced_analyzer.analyze_log_directory(log_files_content)
        
        # Combine all log content for ownership analysis
        combined_content = '\n'.join(log_files_content.values())
        
        # Perform standard ownership analysis
        ownership_result = self.analyze_ownership(crash_context, combined_content)
        
        # Enhance ownership analysis with multi-log insights
        enhanced_result = self._enhance_with_incident_analysis(ownership_result, incident_analysis)
        
        return enhanced_result
    
    def _enhance_with_incident_analysis(self, ownership_result, incident_analysis):
        """Enhance ownership determination with crash correlation analysis insights"""
        # Add crash correlation analysis to the result
        ownership_result['multi_log_analysis'] = incident_analysis
        
        # Adjust confidence based on crash correlation findings
        if incident_analysis['summary'].get('crash_found'):
            # If we found a clear WPEFramework crash, potentially increase confidence
            related_events_count = incident_analysis['summary'].get('related_events_count', 0)
            if related_events_count > 5:  # Many related events might indicate complex issue
                if ownership_result['confidence'] == 'High':
                    ownership_result['confidence'] = 'Medium'
                    ownership_result['confidence_adjustment'] = 'Lowered due to complex crash with many related events'
        
        # Add contextual insights from crash correlation
        contextual_insights = self._generate_contextual_insights(incident_analysis, ownership_result['primary_ownership'])
        ownership_result['contextual_insights'] = contextual_insights
        
        # Update hypothesis with incident context
        original_hypothesis = ownership_result['hypothesis']
        enhanced_hypothesis = self._enhance_hypothesis_with_incidents(original_hypothesis, incident_analysis)
        ownership_result['enhanced_hypothesis'] = enhanced_hypothesis
        
        return ownership_result
    
    def _generate_contextual_insights(self, incident_analysis, primary_ownership):
        """Generate insights based on crash correlation patterns and ownership"""
        insights = []
        
        # Check if WPEFramework crash was detected
        if incident_analysis.get('wpe_framework_crash'):
            crash_info = incident_analysis['wpe_framework_crash']
            insights.append(f"WPEFramework crash detected: {crash_info['description']} at {crash_info['timestamp']}")
        
        # Check for related events during crash
        related_events = incident_analysis.get('related_events', [])
        if related_events:
            insights.append(f"{len(related_events)} related events found in other logs during crash timeframe")
            
            # Group by source file
            files_with_events = set(event['source_file'] for event in related_events)
            if len(files_with_events) > 1:
                insights.append(f"Related events found across {len(files_with_events)} different log files")
        
        # Check crash correlation summary
        summary = incident_analysis.get('summary', {})
        if summary.get('concurrent_events', 0) > 0:
            insights.append(f"{summary['concurrent_events']} concurrent events detected during crash")
        
        return insights
    
    def _enhance_hypothesis_with_incidents(self, original_hypothesis, incident_analysis):
        """Enhance the ownership hypothesis with crash correlation context"""
        crash_context = []
        
        # Add main crash information if found
        if incident_analysis.get('wpe_framework_crash'):
            crash_info = incident_analysis['wpe_framework_crash']
            crash_context.append(f"WPEFramework crash detected: {crash_info['description']}")
        
        # Add related events context
        summary = incident_analysis.get('summary', {})
        if summary.get('related_events_count', 0) > 0:
            crash_context.append(f"{summary['related_events_count']} related events detected across multiple log files")
        
        # Add timeline information
        timeline = incident_analysis.get('timeline_analysis', [])
        if timeline:
            crash_context.append(f"Crash timeline shows {len(timeline)} timestamped events")
        
        if crash_context:
            enhanced_hypothesis = original_hypothesis + " \n\nCrash Correlation Context: " + " | ".join(crash_context)
            return enhanced_hypothesis
        
        return original_hypothesis
    
    def analyze_ownership(self, crash_context, log_content):
        """Determine ownership responsibility based on log patterns with conservative confidence"""
        combined_content = log_content
        
        ownership_evidence = {
            'thunder_plugin': {'high_confidence': [], 'medium_confidence': [], 'low_confidence': []},
            'thunder_core': {'high_confidence': [], 'medium_confidence': [], 'low_confidence': []},
            'comrpc_layer': {'high_confidence': [], 'medium_confidence': [], 'low_confidence': []}
        }
        
        # Analyze patterns for each ownership category with confidence levels
        for category, patterns in self.ownership_patterns.items():
            for pattern_data in patterns:
                if len(pattern_data) == 3:
                    pattern, description, confidence_tier = pattern_data
                else:
                    pattern, description = pattern_data
                    confidence_tier = 'low'  # Default to low confidence
                
                matches = re.findall(pattern, combined_content, re.IGNORECASE)
                if matches:
                    ownership_evidence[category][f'{confidence_tier}_confidence'].append({
                        'pattern': description,
                        'matches': len(matches),
                        'evidence_text': matches[:2],  # First 2 matches as evidence
                        'category': category  # Add category to evidence
                    })
        
        # Special analysis for plugin activation crash with high specificity
        plugin_activation_result = self._analyze_plugin_activation_crash_detailed(log_content)
        if plugin_activation_result:
            ownership_evidence['thunder_plugin']['high_confidence'].append({
                'pattern': f'Plugin {plugin_activation_result["plugin_name"]} activation crash',
                'matches': 1,
                'evidence_text': [plugin_activation_result['crash_detail']],
                'category': 'thunder_plugin'  # Add category to evidence
            })
        
        # Process crash context with conservative interpretation
        if crash_context:
            crashed_process = crash_context.get('crashed_process', '').lower()
            if any(plugin_term in crashed_process for plugin_term in ['plugin', '.so']):
                # Only medium confidence for process name indication
                ownership_evidence['thunder_plugin']['medium_confidence'].append({
                    'pattern': 'Crashed process name suggests plugin',
                    'matches': 1,
                    'evidence_text': [crashed_process],
                    'category': 'thunder_plugin'  # Add category to evidence
                })
            elif any(framework_term in crashed_process for framework_term in ['wpeframework', 'thunder', 'framework']):
                ownership_evidence['thunder_core']['medium_confidence'].append({
                    'pattern': 'Crashed process name suggests Thunder framework',
                    'matches': 1,
                    'evidence_text': [crashed_process],
                    'category': 'thunder_core'  # Add category to evidence
                })
        
        # Determine ownership with conservative confidence assessment
        ownership_result = self._determine_conservative_ownership(ownership_evidence)
        
        return ownership_result
    
    def _analyze_plugin_activation_crash(self, log_content):
        """Analyze if crash happened during or immediately after plugin activation"""
        lines = log_content.split('\n')
        
        for i, line in enumerate(lines):
            # Look for plugin activation patterns
            if re.search(r'Activated\s+plugin.*\[([^\]]+)\]', line, re.IGNORECASE):
                # Check next few lines for crash patterns
                next_lines = lines[i+1:i+5]  # Check next 4 lines
                crash_patterns = [
                    'pure virtual method called',
                    'terminate called',
                    'Signal received',
                    'segmentation fault',
                    'abort()'
                ]
                
                for next_line in next_lines:
                    for crash_pattern in crash_patterns:
                        if crash_pattern.lower() in next_line.lower():
                            return True
        
        return False
    
    def _analyze_plugin_activation_crash_detailed(self, log_content):
        """Detailed analysis of plugin activation crash with specific plugin identification"""
        lines = log_content.split('\n')
        
        for i, line in enumerate(lines):
            # Look for specific plugin activation patterns
            plugin_match = re.search(r'Activated\s+plugin\s+\[([^\]]+)\]', line, re.IGNORECASE)
            if plugin_match:
                plugin_name = plugin_match.group(1)
                # Check next few lines for crash patterns within very short time window
                next_lines = lines[i+1:i+3]  # Only check next 2 lines for immediate crash
                
                high_confidence_crashes = [
                    'pure virtual method called',
                    'terminate called after throwing',
                    'Signal received 11',  # SIGSEGV
                    'segmentation fault'
                ]
                
                for j, next_line in enumerate(next_lines):
                    for crash_pattern in high_confidence_crashes:
                        if crash_pattern.lower() in next_line.lower():
                            return {
                                'plugin_name': plugin_name,
                                'crash_detail': crash_pattern,
                                'line_distance': j + 1
                            }
        
        return None
    
    def _determine_conservative_ownership(self, ownership_evidence):
        """Determine ownership with conservative confidence assessment"""
        # Calculate weighted scores for each category
        category_scores = {}
        
        for category, evidence in ownership_evidence.items():
            high_count = len(evidence['high_confidence'])
            medium_count = len(evidence['medium_confidence'])
            low_count = len(evidence['low_confidence'])
            
            # Weighted scoring: high=3, medium=1, low=0.3
            score = (high_count * 3) + (medium_count * 1) + (low_count * 0.3)
            category_scores[category] = {
                'score': score,
                'high_evidence': high_count,
                'medium_evidence': medium_count,
                'low_evidence': low_count
            }
        
        # Find the category with highest score
        best_category = max(category_scores.keys(), key=lambda x: category_scores[x]['score'])
        best_score_data = category_scores[best_category]
        
        # Conservative confidence determination
        if best_score_data['score'] == 0:
            # No evidence at all
            return self._create_ownership_result(
                'Unknown', 'Low', 
                'No clear ownership indicators found in the crash logs',
                ownership_evidence
            )
        
        # Determine confidence level conservatively
        confidence = 'Low'  # Default to Low as per user requirement
        
        # Only High confidence if we have strong, specific evidence
        if (best_score_data['high_evidence'] >= 2 or 
            (best_score_data['high_evidence'] >= 1 and best_score_data['medium_evidence'] >= 2)):
            confidence = 'High'
        elif best_score_data['high_evidence'] >= 1 or best_score_data['medium_evidence'] >= 3:
            confidence = 'Medium'
        
        # Generate hypothesis
        hypothesis = self._generate_conservative_hypothesis(best_category, ownership_evidence[best_category], confidence)
        
        return self._create_ownership_result(best_category, confidence, hypothesis, ownership_evidence)
    
    def _generate_conservative_hypothesis(self, owner, owner_evidence, confidence_level):
        """Generate conservative ownership hypothesis based on evidence"""
        # Collect all evidence patterns
        all_patterns = []
        for evidence_list in owner_evidence.values():
            all_patterns.extend([item['pattern'] for item in evidence_list])
        
        confidence_qualifier = {
            'High': 'Strong evidence indicates',
            'Medium': 'Evidence suggests',
            'Low': 'Limited evidence points to'
        }.get(confidence_level, 'Evidence suggests')
        
        if owner == 'thunder_plugin':
            if any('activation' in pattern.lower() for pattern in all_patterns):
                return f"{confidence_qualifier} the crash originates from a Thunder plugin during activation or initialization. The plugin may have failed during virtual method setup or object lifecycle management."
            elif any('virtual' in pattern.lower() for pattern in all_patterns):
                return f"{confidence_qualifier} a plugin-related pure virtual method call error, indicating improper object lifecycle or inheritance issues in plugin code."
            else:
                return f"{confidence_qualifier} Thunder plugin-related issues, but the specific plugin and failure mode require further investigation."
        
        elif owner == 'thunder_core':
            if any('worker' in pattern.lower() or 'thread' in pattern.lower() for pattern in all_patterns):
                return f"{confidence_qualifier} Thunder core framework threading or worker pool issues."
            elif any('assert' in pattern.lower() for pattern in all_patterns):
                return f"{confidence_qualifier} Thunder framework assertion failure or core component issue."
            else:
                return f"{confidence_qualifier} Thunder core framework components are involved, but specific root cause needs investigation."
        
        elif owner == 'comrpc_layer':
            return f"{confidence_qualifier} COMRPC layer communication issues or RPC boundary problems between components."
        
        else:
            return "Unable to determine clear Thunder vs Plugin ownership. Phase 3 stack trace analysis recommended."
    
    def _create_ownership_result(self, owner, confidence_level, hypothesis, all_evidence):
        """Create structured ownership analysis result"""
        return {
            'primary_ownership': owner.replace('_', ' ').title(),
            'confidence': confidence_level,
            'hypothesis': hypothesis,
            'evidence_summary': self._summarize_evidence(all_evidence),
            'detailed_evidence': all_evidence,
            'recommendation': self._generate_recommendation(owner, confidence_level),
            'analysis_note': 'Phase 2 uses conservative confidence assessment. Low confidence indicates Phase 3 stack analysis needed for 100% ownership determination.'
        }
    
    def _summarize_evidence(self, evidence_data):
        """Summarize key evidence for ownership determination"""
        evidence = []
        for category, data in evidence_data.items():
            total_evidence = len(data.get('high_confidence', [])) + len(data.get('medium_confidence', [])) + len(data.get('low_confidence', []))
            if total_evidence > 0:
                # Collect patterns from all confidence levels
                all_patterns = []
                for confidence_level in ['high_confidence', 'medium_confidence', 'low_confidence']:
                    patterns = [item['pattern'] for item in data.get(confidence_level, [])]
                    all_patterns.extend(patterns)
                
                evidence.append({
                    'category': category.replace('_', ' ').title(),
                    'high_confidence_count': len(data.get('high_confidence', [])),
                    'medium_confidence_count': len(data.get('medium_confidence', [])),
                    'low_confidence_count': len(data.get('low_confidence', [])),
                    'key_patterns': all_patterns[:3]  # Top 3 patterns
                })
        
        # Sort by high confidence evidence first, then medium, then low
        return sorted(evidence, key=lambda x: (x['high_confidence_count'], x['medium_confidence_count'], x['low_confidence_count']), reverse=True)
    
    def _generate_recommendation(self, owner, confidence):
        """Generate escalation recommendation"""
        recommendations = {
            'thunder_plugin': 'Escalate to Thunder Plugin Development Team',
            'thunder_core': 'Escalate to Thunder Core Framework Team', 
            'comrpc_layer': 'Escalate to COMRPC/RPC Communication Team',
            'framework_startup': 'Escalate to Thunder Framework Architecture Team'
        }
        
        if confidence == 'Low':
            return f"Further investigation needed - Tentatively {recommendations.get(owner, 'Escalate to Thunder Architecture Team')}"
        else:
            return recommendations.get(owner, 'Escalate to Thunder Architecture Team')

# Initialize analyzers
crash_analyzer = CrashAnalyzer()
ownership_analyzer = OwnershipAnalyzer()  # Legacy analyzer for backward compatibility

# Initialize enhanced systems
pattern_manager = DynamicPatternManager()
enhanced_ownership_analyzer = EnhancedOwnershipAnalyzer(pattern_manager)
chat_interface = ChatPatternInterface(pattern_manager)
pattern_import_export = PatternImportExport(pattern_manager)

@app.route('/')
def index():
    """Main dashboard"""
    return render_template('index.html')

def _create_safe_filename(original_filename):
    """Create a safe filename while preserving directory structure for better organization"""
    # For directory uploads, preserve relative path structure
    if '/' in original_filename or '\\' in original_filename:
        # This is likely from a directory upload, preserve structure
        path_parts = original_filename.replace('\\', '/').split('/')
        # Keep last 2-3 directory levels for context
        if len(path_parts) > 3:
            safe_parts = path_parts[-3:]  # Keep last 3 levels
        else:
            safe_parts = path_parts
        
        # Secure each part
        safe_parts = [secure_filename(part) for part in safe_parts if part]
        return '/'.join(safe_parts)
    else:
        # Single file upload
        return secure_filename(original_filename)

@app.route('/upload', methods=['GET', 'POST'])
def upload_logs():
    """Handle traditional log uploads with optional enhanced multi-log analysis"""
    if request.method == 'POST':
        try:
            # Traditional file uploads
            core_log_file = request.files.get('core_log_file')
            wpe_log_file = request.files.get('wpe_log_file')  
            version_file = request.files.get('version_file')
            stacktrace_file = request.files.get('stacktrace_file')
            
            # Optional enhanced analysis
            enhanced_analysis_enabled = request.form.get('enable_enhanced_analysis') == 'on'
            phase3_enabled = request.form.get('enable_phase3') == 'on'
            
            # Validate required core log file
            if not core_log_file or not core_log_file.filename:
                flash('Please select a core log file for analysis.', 'error')
                return redirect(request.url)
            
            # Read core log content
            core_content = core_log_file.read().decode('utf-8', errors='ignore')
            if not core_content.strip():
                flash('Core log file appears to be empty.', 'error')
                return redirect(request.url)
            
            # Read WPE framework log content (optional)
            wpe_content = ''
            if wpe_log_file and wpe_log_file.filename:
                wpe_content = wpe_log_file.read().decode('utf-8', errors='ignore')
            
            # Read version file content (optional)
            version_content = ''
            if version_file and version_file.filename:
                version_content = version_file.read().decode('utf-8', errors='ignore')
            
            # Read stack trace content (Phase 3)
            stacktrace_content = ''
            if phase3_enabled and stacktrace_file and stacktrace_file.filename:
                stacktrace_content = stacktrace_file.read().decode('utf-8', errors='ignore')
            elif phase3_enabled:
                flash('Stack trace file is required when Phase 3 is enabled.', 'warning')
            
            # Prepare additional logs dict with version file if available
            additional_logs = {}
            if version_content:
                additional_logs['version.txt'] = version_content
            
            # Enhanced Phase 2.2: Multi-log directory analysis
            enhanced_analysis_used = False
            if enhanced_analysis_enabled:
                additional_files = request.files.getlist('additional_logs')
                if additional_files and any(f.filename for f in additional_files):
                    enhanced_analysis_used = True
                    processed_files = 0
                    skipped_files = 0
                    
                    # Process additional log files
                    supported_extensions = {'.txt', '.log', '.out', '.err', '.trace'}
                    max_file_size = 50 * 1024 * 1024  # 50MB per file
                    
                    for file in additional_files:
                        if file.filename != '' and file.filename is not None:
                            try:
                                filename = getattr(file, 'webkitRelativePath', file.filename) or file.filename
                                file_ext = os.path.splitext(filename.lower())[1]
                                
                                if file_ext not in supported_extensions:
                                    skipped_files += 1
                                    continue
                                
                                # Check file size
                                file.seek(0, 2)
                                file_size = file.tell()
                                file.seek(0)
                                
                                if file_size > max_file_size:
                                    skipped_files += 1
                                    flash(f'Skipped large file {filename} (>{max_file_size//1024//1024}MB)', 'warning')
                                    continue
                                
                                # Read file content
                                file_content = file.read().decode('utf-8', errors='ignore')
                                if file_content.strip():
                                    safe_filename = _create_safe_filename(filename)
                                    additional_logs[safe_filename] = file_content
                                    processed_files += 1
                                else:
                                    skipped_files += 1
                                    
                            except Exception as e:
                                skipped_files += 1
                                logger.error(f'Error processing file {filename}: {str(e)}')
                                continue
                    
                    if processed_files > 0:
                        flash(f'Enhanced analysis: {processed_files} additional log files processed', 'info')
                        if skipped_files > 0:
                            flash(f'{skipped_files} files were skipped', 'warning')
            
            # Determine analysis phases
            include_phase2 = True  # Always include Phase 2.1
            
            # Perform crash analysis
            if enhanced_analysis_used:
                # Use enhanced multi-log analysis (Phase 2.2)
                result = crash_analyzer.analyze_crash(
                    core_content,
                    wpe_content,
                    additional_logs=additional_logs,
                    stacktrace_content=stacktrace_content,
                    include_phase2=True,
                    include_phase3=phase3_enabled
                )
                analysis_type = 'Enhanced Multi-Log Analysis (Phase 2.2)'
            else:
                # Traditional analysis (Phase 1 & 2.1) 
                result = crash_analyzer.analyze_crash(
                    core_content,
                    wpe_content,
                    additional_logs=additional_logs,
                    stacktrace_content=stacktrace_content,
                    include_phase2=True,
                    include_phase3=phase3_enabled
                )
                analysis_type = 'Traditional Analysis (Phase 1 & 2.1)'
            
            # Handle "no crash found" scenario
            if result.get('no_crash_found', False) or result.get('status') == 'No crash found':
                flash('Analysis completed - No genuine crash detected in the uploaded logs', 'info')
                flash('The logs appear to show normal system operations rather than crash evidence', 'warning')
            else:
                # Provide success feedback
                success_msg = f'{analysis_type} completed successfully'
                if phase3_enabled and stacktrace_content:
                    success_msg += ' | Phase 3 stack trace analysis included'
                flash(success_msg, 'success')
            
            return render_template('results.html', result=result)
            
        except Exception as e:
            logger.error(f'Error in log analysis: {str(e)}')
            flash(f'Error in analysis: {str(e)}', 'error')
            return redirect(request.url)
    
    return render_template('upload.html')

@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    """API endpoint for crash analysis - supports multi-log analysis and Phase 3 stack trace analysis"""
    try:
        data = request.get_json()
        core_log = data.get('core_log', '')
        wpe_log = data.get('wpe_log', '')
        stacktrace_content = data.get('stacktrace_content', '')
        additional_logs = data.get('additional_logs', {})
        include_phase2 = data.get('include_phase2', True)
        include_phase3 = data.get('include_phase3', False)
        multi_log_analysis = data.get('multi_log_analysis', False)
        
        if not core_log:
            return jsonify({'error': 'core_log is required'}), 400
        
        # Perform analysis with optional multi-log and Phase 3 support
        if include_phase2 and multi_log_analysis and additional_logs:
            result = crash_analyzer.analyze_crash(
                core_log, 
                wpe_log, 
                additional_logs=additional_logs,
                stacktrace_content=stacktrace_content,
                include_phase2=True,
                include_phase3=include_phase3
            )
        else:
            result = crash_analyzer.analyze_crash(
                core_log, 
                wpe_log, 
                stacktrace_content=stacktrace_content,
                include_phase2=include_phase2,
                include_phase3=include_phase3
            )
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/patterns')
def patterns():
    """Pattern management interface"""
    try:
        # Get pattern statistics
        pattern_stats = pattern_manager.get_component_stats()
        
        # Load all patterns for display
        all_patterns = pattern_manager.loaded_patterns
        
        return render_template('patterns.html', 
                             pattern_stats=pattern_stats,
                             all_patterns=all_patterns)
    except Exception as e:
        flash(f'Error loading patterns: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/chat')
def chat():
    """Interactive chat interface"""
    try:
        # Get statistics for display
        stats = pattern_manager.get_component_stats()
        total_patterns = sum(component['total_patterns'] for component in stats.values())
        total_components = len(stats)
        
        # Calculate confidence breakdown
        total_high = sum(component['confidence_breakdown'].get('high', 0) for component in stats.values())
        total_medium = sum(component['confidence_breakdown'].get('medium', 0) for component in stats.values())
        total_low = sum(component['confidence_breakdown'].get('low', 0) for component in stats.values())
        
        return render_template('chat.html',
                             current_time=datetime.now().strftime('%H:%M:%S'),
                             total_patterns=total_patterns,
                             total_components=total_components,
                             high_confidence_count=total_high,
                             medium_confidence_count=total_medium,
                             low_confidence_count=total_low)
    except Exception as e:
        flash(f'Error loading chat interface: {str(e)}', 'error')
        return redirect(url_for('index'))

# API Routes for Pattern Management
@app.route('/api/patterns/add', methods=['POST'])
def api_add_pattern():
    """API endpoint to add new patterns"""
    try:
        data = request.get_json()
        
        component = data.get('component')
        pattern = data.get('pattern')
        description = data.get('description')
        confidence = data.get('confidence', 'medium')
        category = data.get('category', 'user_defined')
        
        if not all([component, pattern, description]):
            return jsonify({
                'success': False,
                'error': 'Missing required fields: component, pattern, description'
            })
        
        success, message = pattern_manager.add_user_pattern(
            component, pattern, description, confidence, category
        )
        
        if success:
            # Refresh enhanced analyzer patterns after adding new pattern
            enhanced_ownership_analyzer.refresh_patterns()
            return jsonify({
                'success': True,
                'message': message
            })
        else:
            return jsonify({
                'success': False,
                'error': message
            })
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Server error: {str(e)}'
        })

@app.route('/api/patterns/test', methods=['POST'])
def api_test_pattern():
    """API endpoint to test patterns against log content"""
    try:
        data = request.get_json()
        
        pattern = data.get('pattern')
        log_content = data.get('log_content')
        
        if not pattern or not log_content:
            return jsonify({
                'success': False,
                'error': 'Missing pattern or log content'
            })
        
        success, match_count, matches = pattern_manager.test_pattern_against_log(pattern, log_content)
        
        if success:
            return jsonify({
                'success': True,
                'match_count': match_count,
                'matches': matches[:10]  # Return first 10 matches
            })
        else:
            return jsonify({
                'success': False,
                'error': matches  # Error message is in matches when success=False
            })
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Server error: {str(e)}'
        })

@app.route('/api/patterns/search', methods=['POST'])
def api_search_patterns():
    """API endpoint to search patterns"""
    try:
        data = request.get_json()
        search_term = data.get('search_term', '')
        
        results = pattern_manager.search_patterns(search_term)
        
        return jsonify({
            'success': True,
            'results': results[:20]  # Return first 20 results
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Server error: {str(e)}'
        })

@app.route('/api/patterns/delete', methods=['DELETE'])
def api_delete_pattern():
    """API endpoint to delete user-added patterns"""
    try:
        data = request.get_json()
        component = data.get('component')
        pattern_id = data.get('pattern_id')
        
        if not component or not pattern_id:
            return jsonify({
                'success': False,
                'error': 'Missing component or pattern_id'
            })
        
        # Only allow deletion of user-added patterns
        if component not in pattern_manager.loaded_patterns:
            return jsonify({
                'success': False,
                'error': 'Component not found'
            })
        
        user_patterns = pattern_manager.loaded_patterns[component]['patterns'].get('user_patterns', {})
        
        if 'patterns' not in user_patterns:
            return jsonify({
                'success': False,
                'error': 'No user patterns found'
            })
        
        # Find and remove the pattern
        patterns_list = user_patterns['patterns']
        pattern_found = False
        
        for i, pattern in enumerate(patterns_list):
            if pattern.get('id') == pattern_id:
                patterns_list.pop(i)
                pattern_found = True
                break
        
        if pattern_found:
            # Save the updated patterns
            success = pattern_manager.save_patterns(component)
            if success:
                # Refresh enhanced analyzer patterns after deletion
                enhanced_ownership_analyzer.refresh_patterns()
                return jsonify({
                    'success': True,
                    'message': 'Pattern deleted successfully'
                })
            else:
                return jsonify({
                    'success': False,
                    'error': 'Failed to save after deletion'
                })
        else:
            return jsonify({
                'success': False,
                'error': 'Pattern not found'
            })
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Server error: {str(e)}'
        })

# API Routes for Chat Interface
@app.route('/api/chat/message', methods=['POST'])
def api_chat_message():
    """API endpoint for chat messages"""
    try:
        data = request.get_json()
        
        message = data.get('message', '')
        log_content = data.get('log_content')
        
        if not message:
            return jsonify({
                'success': False,
                'error': 'Empty message'
            })
        
        response = chat_interface.process_chat_message(message, log_content)
        
        # Refresh analyzer patterns if chat added/modified patterns
        enhanced_ownership_analyzer.refresh_patterns()
        
        return jsonify({
            'success': True,
            'response': response
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Chat error: {str(e)}'
        })

@app.route('/api/chat/history', methods=['GET'])
def api_chat_history():
    """API endpoint to get chat history"""
    try:
        history = chat_interface.get_conversation_history()
        return jsonify({
            'success': True,
            'history': history
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Server error: {str(e)}'
        })

@app.route('/api/chat/clear', methods=['POST'])
def api_chat_clear():
    """API endpoint to clear chat history"""
    try:
        chat_interface.clear_history()
        return jsonify({
            'success': True,
            'message': 'Chat history cleared'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Server error: {str(e)}'
        })

# API Routes for Pattern Import/Export
@app.route('/api/patterns/import', methods=['POST'])
def api_import_patterns():
    """API endpoint to import patterns from file"""
    try:
        if 'file' not in request.files:
            return jsonify({
                'success': False,
                'error': 'No file uploaded'
            })
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({
                'success': False,
                'error': 'No file selected'
            })
        
        # Save uploaded file temporarily
        filename = secure_filename(file.filename)
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], f'temp_{filename}')
        file.save(temp_path)
        
        try:
            # Import patterns
            success, message, import_summary = pattern_import_export.import_patterns_from_file(temp_path)
            
            # Clean up temp file
            os.remove(temp_path)
            
            if success:
                # Refresh enhanced analyzer patterns after import
                enhanced_ownership_analyzer.refresh_patterns()
                return jsonify({
                    'success': True,
                    'message': message,
                    'summary': import_summary
                })
            else:
                return jsonify({
                    'success': False,
                    'error': message
                })
                
        except Exception as e:
            # Clean up temp file on error
            if os.path.exists(temp_path):
                os.remove(temp_path)
            raise e
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Import error: {str(e)}'
        })

@app.route('/api/patterns/export/<format_type>')
def api_export_patterns(format_type):
    """API endpoint to export patterns"""
    try:
        components = request.args.getlist('components')
        
        # Create export filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'wpe_patterns_{timestamp}.{format_type}'
        export_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        success, message = pattern_import_export.export_patterns_to_file(
            export_path, format_type, components if components else None
        )
        
        if success:
            return jsonify({
                'success': True,
                'message': message,
                'download_url': f'/download/{filename}'
            })
        else:
            return jsonify({
                'success': False,
                'error': message
            })
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Export error: {str(e)}'
        })

@app.route('/download/<filename>')
def download_file(filename):
    """Download exported files"""
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)
    except FileNotFoundError:
        return jsonify({'error': 'File not found'}), 404

@app.route('/health')
def health_check():
    """Enhanced health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'WPE Crash Analyzer - Enhanced with Dynamic Pattern Management',
        'version': '2.0 - Enhanced',
        'phases_available': ['Phase 1', 'Phase 2 Enhanced', 'Phase 3'],
        'current_capabilities': [
            'Crash Discovery & Process Identification',
            'Enhanced Multi-Component Ownership Analysis',
            'Dynamic Pattern Management for All RDK Components',
            'Interactive Chat Assistant for Pattern Management',
            'Pattern Import/Export (JSON, CSV, Text formats)',
            'Multi-Log Directory Upload & Analysis',
            'WPEFramework Crash Detection',
            'Cross-Log Crash Correlation',
            'Crash Timeline Analysis',
            'Related Events Detection During Crash',
            'Stack Trace Analysis & Call Stack Parsing',
            'MAC Address Validation Between Logs',
            'Confirmed Ownership Determination',
            'Symbol Resolution & Framework vs Plugin Code Identification',
            'Thread Analysis & Boundary Crossing Detection',
            'HAL Manager Analysis (dsMgr, mfrMgr, sysMgr, etc.)',  
            'IARM Bus Communication Analysis',
            'Media Component Analysis (rmfStreamer, audio)',
            'Security Component Analysis (SecManager, authservice)',
            'Network Service Analysis (tr69hostif, bluetooth)',
            'System Service Analysis (parodus, lighttpd, etc.)'
        ],
        'supported_components': [
            'Thunder Framework Core',
            'Thunder Plugins', 
            'HAL Managers',
            'IARM Components',
            'Media Components',
            'Security Components',
            'Network Components', 
            'System Services',
            'COMRPC Layer'
        ],
        'pattern_statistics': pattern_manager.get_component_stats() if 'pattern_manager' in globals() else {}
    })

@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(e):
    """Handle file upload size limit exceeded"""
    flash('Upload size too large. Maximum allowed: 500MB total. Please reduce the size of your directory or split into smaller uploads.', 'error')
    return redirect(url_for('upload_logs'))

@app.errorhandler(413)
def handle_payload_too_large(e):
    """Handle 413 Payload Too Large error"""
    flash('Upload size exceeded server limits (500MB max). Please upload a smaller directory or contact administrator.', 'error')
    return redirect(url_for('upload_logs'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
