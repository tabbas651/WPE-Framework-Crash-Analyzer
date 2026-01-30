#!/usr/bin/env python3
"""
WPE Framework Crash Analysis Web Application
Phase 1: Crash Discovery & Process Identification
"""

from flask import Flask, render_template, request, jsonify, flash, redirect, url_for
import os
import re
import json
from datetime import datetime
from werkzeug.utils import secure_filename
import logging

app = Flask(__name__)
app.secret_key = 'wpe_crash_analysis_secret_key'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

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
    
    def extract_device_info(self, log_content):
        """Extract MAC address and image version from logs"""
        mac_pattern = r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})|([0-9A-Fa-f]{12})'
        version_pattern = r'version[:\s]+([0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9]*)'
        
        mac_matches = re.findall(mac_pattern, log_content, re.IGNORECASE)
        version_matches = re.findall(version_pattern, log_content, re.IGNORECASE)
        
        mac_address = None
        if mac_matches:
            # Clean up MAC address format
            for match in mac_matches:
                if match[0] and match[1]:  # Standard MAC format
                    mac_address = f"{match[0]}{match[1]}"
                    break
                elif match[2]:  # Continuous format
                    mac_address = match[2]
                    break
        
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

    def identify_crash_signal(self, log_content):
        """Identify crash signal from log content with improved detection"""
        # Look for explicit signal patterns first
        signal_patterns = [
            (r'signal\s+(\d+)', {
                '11': 'SIGSEGV', '6': 'SIGABRT', '9': 'SIGKILL', 
                '5': 'SIGTRAP', '8': 'SIGFPE', '7': 'SIGBUS',
                '15': 'SIGTERM', '2': 'SIGINT'
            }),
            (r'(SIGSEGV|SIGABRT|SIGKILL|SIGTRAP|SIGFPE|SIGBUS|SIGTERM|SIGINT)', None),
            (r'segmentation\s+fault', 'SIGSEGV'),
            (r'abort(?:ed)?', 'SIGABRT'),
            (r'killed', 'SIGKILL'),
            (r'floating\s+point', 'SIGFPE'),
            (r'bus\s+error', 'SIGBUS')
        ]
        
        for pattern, mapping in signal_patterns:
            matches = re.findall(pattern, log_content, re.IGNORECASE)
            if matches:
                if mapping is None:
                    return matches[0].upper()
                elif isinstance(mapping, dict):
                    signal_num = matches[0]
                    return mapping.get(signal_num, f'Signal {signal_num}')
                else:
                    return mapping
        
        return 'Unknown'
    
    def identify_crashed_process(self, log_content):
        """Identify which process crashed by looking for specific crash indicators"""
        # First, look for explicit crash indicators
        crash_indicators = [
            r'Process crashed\s*=\s*([^\s,\]]+)',
            r'CRASH.*Process[:\s]+([^\s,\]]+)',
            r'Crashed process[:\s]+([^\s,\]]+)',
            r'\[CRASH[^\]]*\].*Process[:\s]+([^\s,\]]+)',
            r'Signal.*delivered to process[:\s]+([^\s,\]]+)',
            r'Core dump.*process[:\s]+([^\s,\]]+)'
        ]
        
        for pattern in crash_indicators:
            matches = re.findall(pattern, log_content, re.IGNORECASE)
            if matches:
                # Return the first explicit crash process found
                return [matches[0].strip()]
        
        # If no explicit crash indicator, look for signal-related crashes
        signal_crashes = [
            r'([^\s]+)\s+received signal',
            r'([^\s]+)\s+terminated by signal',
            r'([^\s]+)\s+segmentation fault',
            r'([^\s]+)\s+abort'
        ]
        
        for pattern in signal_crashes:
            matches = re.findall(pattern, log_content, re.IGNORECASE)
            if matches:
                return [matches[0].strip()]
        
        # Last resort: look for general process patterns but with crash context
        crash_context_patterns = [
            r'(wpeframework|WPEFramework).*(?:crash|abort|signal|fault)',
            r'(thunder|Thunder).*(?:crash|abort|signal|fault)',
            r'(plugin|Plugin).*(?:crash|abort|signal|fault)',
            r'(?:crash|abort|signal|fault).*(wpeframework|WPEFramework)',
            r'(?:crash|abort|signal|fault).*(thunder|Thunder)',
            r'(?:crash|abort|signal|fault).*(plugin|Plugin)'
        ]
        
        for pattern in crash_context_patterns:
            matches = re.findall(pattern, log_content, re.IGNORECASE)
            if matches:
                return [matches[0].strip()]
        
        return ['Unknown']
    
    def extract_crash_timestamp(self, log_content):
        """Extract crash timestamp from logs with improved accuracy"""
        # Look for crash-specific timestamps first
        crash_timestamp_patterns = [
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z)\s+\[CRASH',
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z).*[Pp]rocess crashed',
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z).*crash',
            r'(\d{6}-\d{2}:\d{2}:\d{2}\.\d{3}).*[Pp]rocess crashed',
            r'(\d{2}:\d{2}:\d{2}\.\d{3}).*[Pp]rocess crashed'
        ]
        
        for pattern in crash_timestamp_patterns:
            matches = re.findall(pattern, log_content, re.IGNORECASE)
            if matches:
                return matches[0]
        
        # Fallback to general timestamp patterns
        general_patterns = [
            r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z',
            r'\d{6}-\d{2}:\d{2}:\d{2}\.\d{3}',
            r'\d{2}:\d{2}:\d{2}\.\d{3}',
            r'\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}'
        ]
        
        timestamps = []
        for pattern in general_patterns:
            matches = re.findall(pattern, log_content)
            timestamps.extend(matches)
        
        return timestamps[-1] if timestamps else 'Unknown'
    
    def extract_last_meaningful_logs(self, log_content, context_lines=10):
        """Extract meaningful log entries around signal crash with context"""
        lines = [line.strip() for line in log_content.split('\n') if line.strip()]
        
        # Look for signal crash patterns
        signal_patterns = [
            r'Signal received \d+\. in process',
            r'signal \d+ received',
            r'terminate called',
            r'pure virtual method called',
            r'segmentation fault',
            r'abort\(\) called'
        ]
        
        signal_line_index = -1
        signal_line_content = ""
        
        # Find the last signal occurrence
        for i, line in enumerate(lines):
            for pattern in signal_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    signal_line_index = i
                    signal_line_content = line
                    break
        
        # If we found a signal line, extract context around it
        if signal_line_index != -1:
            start_index = max(0, signal_line_index - context_lines)
            end_index = min(len(lines), signal_line_index + context_lines + 1)
            
            context_lines_result = []
            for i in range(start_index, end_index):
                line_marker = " >>> " if i == signal_line_index else "     "
                context_lines_result.append(f"{line_marker}{lines[i]}")
            
            return context_lines_result
        
        # Fallback: look for other crash-related entries
        crash_keywords = ['crash', 'abort', 'fault', 'terminated', 'core dump', 'exception']
        crash_entries = []
        
        for line in reversed(lines):
            if any(keyword in line.lower() for keyword in crash_keywords):
                crash_entries.append(line)
                if len(crash_entries) >= context_lines * 2:
                    break
        
        return list(reversed(crash_entries)) if crash_entries else ["No meaningful crash context found"]

    def analyze_crash(self, core_log_content, wpe_log_content='', include_phase2=True):
        """Main crash analysis function for Phase 1 and optionally Phase 2"""
        combined_content = core_log_content + '\n' + wpe_log_content
        
        # Extract device information
        mac_address, image_version = self.extract_device_info(combined_content)
        
        # Extract crash context
        crash_context = self.extract_crash_context(combined_content)
        
        # Identify crash details - prioritize core_log for crash identification
        crashed_processes = self.identify_crashed_process(core_log_content)
        crash_signal = self.identify_crash_signal(combined_content)
        crash_timestamp = self.extract_crash_timestamp(combined_content)
        last_logs = self.extract_last_meaningful_logs(combined_content)
        
        # Use crash context if available for more accurate process identification
        if 'crashed_process' in crash_context:
            crashed_processes = [crash_context['crashed_process']]
        
        analysis_result = {
            'device_info': {
                'mac_address': mac_address or 'Not found',
                'image_version': image_version or 'Not found'
            },
            'crash_details': {
                'crashed_process': crashed_processes,
                'signal': crash_signal,
                'timestamp': crash_timestamp,
                'last_meaningful_logs': last_logs,
                'crash_context': crash_context
            },
            'phase': 'Phase 1 - Crash Discovery & Process Identification',
            'status': 'completed',
            'confidence': self._calculate_confidence(crash_signal, crashed_processes, mac_address, image_version)
        }
        
        # Phase 2: Ownership Analysis
        if include_phase2:
            ownership_analyzer = OwnershipAnalyzer()
            ownership_result = ownership_analyzer.analyze_ownership(crash_context, combined_content)
            
            analysis_result['ownership_analysis'] = ownership_result
            analysis_result['phase'] = 'Phase 1 & 2 - Crash Discovery & Ownership Analysis'
            
            # Update overall confidence based on ownership confidence
            if ownership_result['confidence'] == 'High':
                analysis_result['overall_confidence'] = 'High'
            elif ownership_result['confidence'] == 'Medium' and analysis_result['confidence'] in ['Medium', 'High']:
                analysis_result['overall_confidence'] = 'Medium'
            else:
                analysis_result['overall_confidence'] = 'Low'
        
        return analysis_result
    
    def _calculate_confidence(self, signal, processes, mac, version):
        """Calculate confidence level based on extracted information"""
        score = 0
        
        # Higher weight for crash-specific information
        if signal != 'Unknown': score += 30
        if processes != ['Unknown'] and 'Unknown' not in processes: score += 30
        if mac and mac != 'Not found': score += 20
        if version and version != 'Not found': score += 20
        
        if score >= 80: return 'High'
        elif score >= 50: return 'Medium'
        else: return 'Low'


class OwnershipAnalyzer:
    """Phase 2 Thunder vs Plugin Responsibility Analysis"""
    
    def __init__(self):
        # Thunder-specific log pattern heuristics for ownership determination
        self.ownership_patterns = {
            'thunder_plugin': [
                (r'Activated plugin.*pure\s+virtual\s+method', 'Plugin activation followed by pure virtual method error'),
                (r'plugin.*Activated.*terminate\s+called', 'Plugin activation followed by termination'),
                (r'UserSettings.*pure\s+virtual|pure\s+virtual.*UserSettings', 'UserSettings plugin virtual method issue'),
                (r'Activated\s+plugin.*\[([^\]]+)\].*(?:pure\s+virtual|terminate\s+called|Signal\s+received)', 'Plugin activation immediately followed by crash'),
                (r'Initialize\(\).*crash|crash.*Initialize\(\)', 'Plugin failed during startup'),
                (r'Deinitialize\(\).*crash|crash.*Deinitialize\(\)', 'Plugin lifecycle exit'),
                (r'segmentation\s+fault.*after.*plugin.*API', 'Plugin misuse or null dereference'),
                (r'plugin.*Initialize.*failed|failed.*plugin.*Initialize', 'Plugin initialization failure'),
                (r'plugin.*exception|exception.*plugin', 'Plugin-specific exception'),
                (r'lib\w+Plugin.*crash|crash.*lib\w+Plugin', 'Plugin library crash'),
                (r'Plugin.*pure\s+virtual|pure\s+virtual.*Plugin', 'Plugin virtual method issue'),
                (r'org\.rdk\.\w+.*(?:pure\s+virtual|terminate\s+called|Signal\s+received)', 'RDK plugin crash pattern')
            ],
            'thunder_core': [
                (r'Core::WorkerPool.*crash|crash.*Core::WorkerPool', 'Framework-level thread issue'),
                (r'MessageDispatcher.*failure|failure.*MessageDispatcher', 'Messaging engine problem'),
                (r'Signal.*SIGABRT.*abort\(\)', 'Assert failure in Thunder core'),
                (r'Thunder.*core.*crash|crash.*Thunder.*core', 'Thunder core framework issue'),
                (r'WorkerPool.*thread.*crash|thread.*WorkerPool.*crash', 'Worker thread management issue'),
                (r'WPEFramework.*core.*crash|crash.*WPEFramework.*core', 'WPEFramework core issue'),
                (r'Framework.*assert|assert.*Framework', 'Framework assertion failure')
            ],
            'comrpc_layer': [
                (r'COMRPC::Invoke.*error|error.*COMRPC::Invoke', 'RPC boundary issue'),
                (r'COMRPC.*crash|crash.*COMRPC', 'COMRPC layer failure'),
                (r'RPC.*call.*failed|failed.*RPC.*call', 'RPC communication failure'),
                (r'COMRPC.*timeout|timeout.*COMRPC', 'RPC timeout issue')
            ],
            'framework_startup': [
                (r'JSON.*parsing.*error|error.*JSON.*parsing', 'Early startup or configuration problem'),
                (r'config.*error|error.*config', 'Configuration issue'),
                (r'startup.*failed|failed.*startup', 'Framework startup failure')
            ]
        }
    
    def analyze_ownership(self, crash_context, log_content):
        """Determine ownership responsibility based on log patterns"""
        combined_content = log_content.lower()
        
        ownership_scores = {
            'thunder_plugin': {'score': 0, 'evidence': []},
            'thunder_core': {'score': 0, 'evidence': []},
            'comrpc_layer': {'score': 0, 'evidence': []},
            'framework_startup': {'score': 0, 'evidence': []}
        }
        
        # Special analysis for plugin activation patterns
        plugin_activation_score = self._analyze_plugin_activation_crash(log_content)
        if plugin_activation_score > 0:
            ownership_scores['thunder_plugin']['score'] += plugin_activation_score
            ownership_scores['thunder_plugin']['evidence'].append({
                'pattern': 'Plugin activation crash pattern detected',
                'matches': 1,
                'evidence_text': ['Plugin activated followed by crash']
            })
        
        # Analyze patterns for each ownership category
        for category, patterns in self.ownership_patterns.items():
            for pattern, description in patterns:
                matches = re.findall(pattern, combined_content, re.IGNORECASE)
                if matches:
                    ownership_scores[category]['score'] += len(matches) * 10
                    ownership_scores[category]['evidence'].append({
                        'pattern': description,
                        'matches': len(matches),
                        'evidence_text': matches[:3]  # First 3 matches as evidence
                    })
        
        # Additional scoring based on crash context
        if crash_context:
            crashed_process = crash_context.get('crashed_process', '').lower()
            if 'plugin' in crashed_process:
                ownership_scores['thunder_plugin']['score'] += 15
                ownership_scores['thunder_plugin']['evidence'].append({
                    'pattern': 'Crashed process indicates plugin',
                    'matches': 1,
                    'evidence_text': [crashed_process]
                })
            elif 'wpeframework' in crashed_process or 'thunder' in crashed_process:
                ownership_scores['thunder_core']['score'] += 15
                ownership_scores['thunder_core']['evidence'].append({
                    'pattern': 'Crashed process indicates Thunder framework',
                    'matches': 1,
                    'evidence_text': [crashed_process]
                })
        
        # Determine primary ownership
        max_score = max(ownership_scores.values(), key=lambda x: x['score'])['score']
        if max_score == 0:
            return self._create_ownership_result('Unknown', 0, 'Low', 'No clear ownership patterns found', ownership_scores)
        
        primary_owner = max(ownership_scores.keys(), key=lambda x: ownership_scores[x]['score'])
        confidence_percentage, confidence_level = self._calculate_ownership_confidence(
            ownership_scores[primary_owner]['score'], max_score, ownership_scores)
        
        # Generate hypothesis
        hypothesis = self._generate_ownership_hypothesis(primary_owner, ownership_scores[primary_owner])
        
        return self._create_ownership_result(primary_owner, confidence_percentage, confidence_level, hypothesis, ownership_scores)
    
    def _analyze_plugin_activation_crash(self, log_content):
        """Analyze if crash happened during or immediately after plugin activation"""
        lines = log_content.split('\n')
        plugin_activation_score = 0
        
        for i, line in enumerate(lines):
            # Look for plugin activation patterns
            if re.search(r'Activated\s+plugin.*\[([^\]]+)\]', line, re.IGNORECASE):
                plugin_name = re.findall(r'Activated\s+plugin.*\[([^\]]+)\]', line, re.IGNORECASE)
                
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
                            plugin_activation_score += 25
                            break
                
                # Special high score for UserSettings + pure virtual pattern
                if any('usersettings' in name.lower() for name in plugin_name):
                    for next_line in next_lines:
                        if 'pure virtual method called' in next_line.lower():
                            plugin_activation_score += 30
                            break
        
        return plugin_activation_score
    
    def _calculate_ownership_confidence(self, owner_score, max_score, all_scores):
        """Calculate confidence percentage for ownership determination"""
        total_score = sum(data['score'] for data in all_scores.values())
        
        if total_score == 0:
            return 0, 'Low'
        
        # Calculate percentage confidence
        confidence_percentage = round((owner_score / total_score) * 100)
        
        # Determine confidence level
        if confidence_percentage >= 70:
            confidence_level = 'High'
        elif confidence_percentage >= 50:
            confidence_level = 'Medium'
        else:
            confidence_level = 'Low'
        
        return confidence_percentage, confidence_level
    
    def _generate_ownership_hypothesis(self, owner, owner_data):
        """Generate ownership hypothesis based on evidence"""
        if owner == 'thunder_plugin':
            # Look for specific plugin issues in evidence
            evidence_patterns = [item['pattern'] for item in owner_data['evidence']]
            if any('activation' in pattern.lower() for pattern in evidence_patterns):
                return "The crash likely originates from a Thunder plugin during activation or initialization. The timing suggests the plugin failed to properly initialize its virtual methods or destructors."
            elif any('pure virtual' in pattern.lower() for pattern in evidence_patterns):
                return "The crash appears to be a plugin-related pure virtual method call, indicating improper object lifecycle management in the plugin code."
            else:
                return "The crash likely originates from Thunder plugin-related code or plugin lifecycle issues."
        elif owner == 'thunder_core':
            return "The crash appears to be in Thunder core framework components, threading, or messaging."
        elif owner == 'comrpc_layer':
            return "The crash seems related to COMRPC layer communication or RPC boundary issues."
        elif owner == 'framework_startup':
            return "The crash appears to be in framework-level components, configuration, or startup sequence."
        else:
            return "Unable to determine clear Thunder vs Plugin ownership from available log patterns."
    
    def _create_ownership_result(self, owner, confidence_percentage, confidence_level, hypothesis, all_scores):
        """Create structured ownership analysis result"""
        return {
            'primary_ownership': owner.replace('_', ' ').title(),
            'confidence_percentage': confidence_percentage,
            'confidence': confidence_level,
            'hypothesis': hypothesis,
            'evidence_summary': self._summarize_evidence(all_scores),
            'detailed_scores': all_scores,
            'recommendation': self._generate_recommendation(owner, confidence_level)
        }
    
    def _summarize_evidence(self, scores):
        """Summarize key evidence for ownership determination"""
        evidence = []
        for category, data in scores.items():
            if data['score'] > 0:
                evidence.append({
                    'category': category.replace('_', ' ').title(),
                    'score': data['score'],
                    'key_patterns': [item['pattern'] for item in data['evidence'][:2]]
                })
        return sorted(evidence, key=lambda x: x['score'], reverse=True)
    
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
ownership_analyzer = OwnershipAnalyzer()

@app.route('/')
def index():
    """Main dashboard"""
    return render_template('index.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload_logs():
    """Handle log file uploads"""
    if request.method == 'POST':
        core_log = request.files.get('core_log')
        wpe_log = request.files.get('wpe_log')
        phase2_enabled = request.form.get('enable_phase2') == 'on'
        
        if not core_log or core_log.filename == '':
            flash('Please upload at least the core log file', 'error')
            return redirect(request.url)
        
        try:
            # Read file contents
            core_content = core_log.read().decode('utf-8', errors='ignore')
            wpe_content = wpe_log.read().decode('utf-8', errors='ignore') if wpe_log else ''
            
            # Perform analysis (Phase 1 + Phase 2 if enabled)
            result = crash_analyzer.analyze_crash(core_content, wpe_content, include_phase2=phase2_enabled)
            
            return render_template('results.html', result=result)
            
        except Exception as e:
            flash(f'Error analyzing logs: {str(e)}', 'error')
            return redirect(request.url)
    
    return render_template('upload.html')

@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    """API endpoint for crash analysis"""
    try:
        data = request.get_json()
        core_log = data.get('core_log', '')
        wpe_log = data.get('wpe_log', '')
        include_phase2 = data.get('include_phase2', True)
        
        if not core_log:
            return jsonify({'error': 'core_log is required'}), 400
        
        result = crash_analyzer.analyze_crash(core_log, wpe_log, include_phase2=include_phase2)
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy', 
        'service': 'WPE Crash Analyzer', 
        'phases_available': ['Phase 1', 'Phase 2'],
        'current_capabilities': [
            'Crash Discovery & Process Identification',
            'Thunder vs Plugin Ownership Analysis'
        ]
    })

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
