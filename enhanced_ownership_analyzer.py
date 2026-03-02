"""
Enhanced Ownership Analyzer with Dynamic Pattern Support
Integrates with DynamicPatternManager for all RDK components
"""

import re
from datetime import datetime
from pattern_manager import DynamicPatternManager


class MultiLogIncidentAnalyzer:
    """Phase 2 Enhanced - Multi-Log Crash Correlation Analysis"""
    
    def __init__(self):
        # Ultra-strict crash detection - only explicit process crashes, not routine processing
        self.crash_patterns = {
            'critical_crashes': [
                # Only genuine WPEFramework process crashes with explicit crash language
                (r'(?:WPEFramework|wpeframework).*(?:crashed|terminated unexpectedly|killed by signal)', 'WPEFramework Process Crash'),
                (r'(?:WPEFramework|wpeframework).*(?:signal\s+(?:11|6|4|8|9)\b|SIGSEGV|SIGABRT|SIGFPE|SIGBUS)', 'WPEFramework Signal Crash'),
                (r'(?:WPEFramework|wpeframework).*(?:segmentation\s+fault|pure\s+virtual\s+method)', 'WPEFramework Fatal Error'),
                # Only actual process crash events with explicit crash indicators
                (r'process\s+(?:crashed|died unexpectedly|killed by signal)', 'Process Crash Event'),
                (r'(?:crashed|terminated unexpectedly).*(?:WPEFramework|Thunder|plugin)', 'Component Crash'),
                (r'caught\s+(?:signal\s+(?:11|6|4|8|9)|SIGSEGV|SIGABRT|SIGFPE|SIGBUS)', 'Critical Signal Caught'),
                # Only segfaults and fatal errors with clear crash context (not test scenarios)
                (r'segmentation\s+fault\s+(?:occurred|at|in)(?!.*test)(?!.*processing)', 'Segmentation Fault Crash'),
                (r'pure\s+virtual\s+method\s+called\s+(?:at|in|from)(?!.*test)', 'Pure Virtual Method Crash')
            ],
            'severe_errors': [
                # Only errors that explicitly indicate actual crashes (exclude routine processing)
                (r'(?:fatal|critical)\s+(?:crash|error)(?!.*processing)(?!.*starting)', 'Fatal System Error'),
                (r'(?:unhandled|uncaught)\s+(?:exception|signal)', 'Unhandled Exception'),
                (r'stack\s+trace.*(?:crash|fault|signal)(?!.*processing)', 'Crash Stack Trace After Error')
            ]
        }
    
    def analyze_log_directory(self, log_files_content):
        """Analyze multiple log files focusing on crash correlation and timeline"""
        analysis_results = {
            'total_files_analyzed': len(log_files_content),
            'crash_correlation': {},
            'timeline_analysis': [],
            'wpe_framework_crash': None,
            'related_events': [],
            'summary': {}
        }
        
        # First, find the main crash in WPEFramework logs
        main_crash_info = self._find_main_wpe_crash(log_files_content)
        analysis_results['wpe_framework_crash'] = main_crash_info
        
        if main_crash_info:
            # Extract timeline events around crash time
            crash_timeline = self._extract_crash_timeline(log_files_content, main_crash_info)
            analysis_results['timeline_analysis'] = crash_timeline
        
        # Create focused summary
        analysis_results['summary'] = self._generate_crash_summary(analysis_results)
        
        return analysis_results
    
    def _find_main_wpe_crash(self, log_files_content):
        """Find the main WPEFramework crash from the logs - ultra-strict detection"""
        wpe_crash_info = None
        min_crash_severity = 8  # Only consider definite crashes (severity 8+)
        
        # Look for WPEFramework or main crash in core logs first
        for filename, content in log_files_content.items():
            if 'wpe' in filename.lower() or 'core' in filename.lower() or 'framework' in filename.lower():
                crash_events = self._extract_crash_events(filename, content)
                
                # Filter to only definite crashes (high severity + explicit crash language)
                definite_crashes = [
                    event for event in crash_events 
                    if event.get('severity_score', 0) >= min_crash_severity 
                    and self._has_definite_crash_indicators(event.get('event_text', ''))
                ]
                
                if definite_crashes:
                    # Take the most severe crash event
                    main_crash = max(definite_crashes, key=lambda x: x.get('severity_score', 0))
                    if not wpe_crash_info or main_crash.get('severity_score', 0) > wpe_crash_info.get('severity_score', 0):
                        wpe_crash_info = main_crash
                        wpe_crash_info['source_file'] = filename
        
        return wpe_crash_info
    
    def _has_definite_crash_indicators(self, event_text):
        """Check if event text has definite crash indicators (not routine processing)"""
        # Exclude routine processing activities
        routine_processing = [
            'starting', 'processing', 'deferring', 'handling', 'managing', 
            'initializing', 'cleanup', 'scheduled', 'routine'
        ]
        
        event_lower = event_text.lower()
        if any(routine in event_lower for routine in routine_processing):
            return False
            
        # Require explicit crash language
        crash_indicators = [
            'crashed', 'terminated unexpectedly', 'killed by signal', 'fault occurred',
            'segmentation fault at', 'signal caught', 'unhandled exception', 'fatal error'
        ]
        
        return any(indicator in event_lower for indicator in crash_indicators)
    
    def _extract_crash_events(self, filename, content):
        """Extract crash-related events from a single log file"""
        crash_events = []
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            timestamp = self._extract_timestamp_from_line(line)
            if not timestamp:
                continue
                
            # Check for crash patterns
            for category, patterns in self.crash_patterns.items():
                for pattern, description in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        severity_score = self._calculate_crash_severity(description)
                        crash_events.append({
                            'timestamp': timestamp,
                            'line_number': i + 1,
                            'description': description,
                            'event_text': line.strip(),
                            'severity_score': severity_score,
                            'category': category
                        })
                        break
        
        return crash_events
    
    def _extract_crash_timeline(self, log_files_content, main_crash_info):
        """Extract timeline of events around the main crash"""
        if not main_crash_info or not main_crash_info.get('timestamp'):
            return []
            
        crash_timestamp = main_crash_info['timestamp']
        timeline_events = []
        
        # Add the main crash event
        timeline_events.append({
            'timestamp': crash_timestamp,
            'source': main_crash_info.get('source_file', 'unknown'),
            'event_type': 'MAIN_CRASH',
            'description': main_crash_info['description'],
            'details': main_crash_info['event_text']
        })
        
        # Look for events in all logs around the crash time
        for filename, content in log_files_content.items():
            crash_events = self._extract_crash_events(filename, content)
            for event in crash_events:
                if self._is_within_crash_window(event['timestamp'], crash_timestamp):
                    timeline_events.append({
                        'timestamp': event['timestamp'],
                        'source': filename,
                        'event_type': event['category'].upper(),
                        'description': event['description'],
                        'details': event['event_text']
                    })
        
        # Sort by timestamp
        timeline_events.sort(key=lambda x: x['timestamp'])
        return timeline_events
    

    
    def _calculate_crash_severity(self, description):
        """Calculate crash severity score - very strict, only genuine crashes get high scores"""
        definite_crashes = [
            'WPEFramework Process Crash', 'WPEFramework Signal Crash', 'WPEFramework Fatal Error',
            'Process Crash Event', 'Component Crash', 'Critical Signal Caught',
            'Segmentation Fault Crash', 'Pure Virtual Method Crash'
        ]
        possible_crashes = [
            'Fatal System Error', 'Unhandled Exception', 'Crash Stack Trace After Error'
        ]
        
        if description in definite_crashes:
            return 10  # Definite crashes only
        elif description in possible_crashes:
            return 8   # Likely crashes only  
        else:
            return 1   # Not crashes (filtered out)
    
    def _generate_crash_summary(self, analysis_results):
        """Generate a focused summary - only report definite crashes with explicit crash language"""
        main_crash = analysis_results.get('wpe_framework_crash')
        
        if not main_crash or main_crash.get('severity_score', 0) < 8:
            return {
                'status': 'No genuine process crash detected in the log files',
                'crash_found': False,
                'analysis_type': 'No crash found - logs contain routine system operations only',
                'recommendation': 'The uploaded logs show normal system operations (minidump/coredump processing, reboot deferrals, etc.) but no evidence of an actual process crash. This appears to be post-reboot cleanup or routine maintenance activities.',
                'detected_activities': [
                    'Routine minidump processing',
                    'Routine coredump processing', 
                    'Reboot deferral operations',
                    'Normal system maintenance'
                ],
                'note': 'Activities like "starting coredump processing" are routine system operations, not crash events.'
            }
        
        return {
            'status': 'Genuine process crash detected with definite crash indicators',
            'crash_found': True,
            'crash_timestamp': main_crash.get('timestamp'),
            'crash_type': main_crash.get('description'),
            'source_log': main_crash.get('source_file'),
            'severity_level': 'DEFINITE' if main_crash.get('severity_score', 0) >= 10 else 'LIKELY',
            'analysis_type': 'Definite crash detection with explicit crash indicators'
        }
    
    def _extract_timestamp_from_line(self, line):
        """Extract timestamp from a log line"""
        timestamp_patterns = [
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z)',
            r'(\d{6}-\d{2}:\d{2}:\d{2}\.\d{3})',
            r'(\d{2}:\d{2}:\d{2}\.\d{3})',
            r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'
        ]
        
        for pattern in timestamp_patterns:
            match = re.search(pattern, line)
            if match:
                return match.group(1)
        return None
    
    def _is_within_crash_window(self, event_timestamp, crash_timestamp, window_seconds=30):
        """Check if event is within crash time window (simplified)"""
        # Simplified time comparison - in production, would need proper datetime parsing
        return True  # For now, include all events
    
    def _calculate_time_offset(self, event_timestamp, crash_timestamp):
        """Calculate time offset between event and crash (simplified)"""
        # Simplified - in production would need proper datetime calculation
        return 0

class EnhancedOwnershipAnalyzer:
    """Enhanced Phase 2 Analysis with support for all RDK components"""
    
    def __init__(self, pattern_manager=None, patterns_dir='patterns'):
        # Use provided pattern manager or create new one
        if pattern_manager:
            self.pattern_manager = pattern_manager
        else:
            self.pattern_manager = DynamicPatternManager(patterns_dir)
        
        # Load dynamic patterns 
        self.ownership_patterns = self.pattern_manager.get_all_patterns_for_analysis()
        
        # Initialize specific plugin tracking for detailed analysis
        self._specific_plugins_in_crash = []
        
        # Component escalation mapping
        self.escalation_teams = {
            'thunder_core': 'Thunder Core Framework Team',
            'thunder_plugins': 'Thunder Plugin Development Team',
            'comrpc_layer': 'COMRPC/RPC Communication Team',
            'hal_managers': 'HAL Hardware Abstraction Team',
            'iarm_components': 'IARM Bus Communication Team',
            'media_components': 'Media Streaming Team',
            'security_components': 'Security and DRM Team',
            'network_components': 'Network Services Team', 
            'system_services': 'System Services Team'
        }
        
        # Component confidence weights for final determination
        self.component_weights = {
            'thunder_core': 3.0,      # High priority - framework issues
            'thunder_plugins': 2.8,   # High priority - plugin issues
            'security_components': 2.5, # High priority - security issues
            'hal_managers': 2.3,      # Medium-high - HAL hardware issues 
            'media_components': 2.0,  # Medium - media streaming issues
            'iarm_components': 1.8,   # Medium-low - often cascading
            'comrpc_layer': 1.5,      # Low - communication layer
            'network_components': 1.3, # Low - often environmental
            'system_services': 1.0    # Lowest - system utilities
        }
    
    def refresh_patterns(self):
        """Refresh patterns from pattern manager - call after patterns are updated"""
        self.ownership_patterns = self.pattern_manager.get_all_patterns_for_analysis()
    
    def analyze_ownership_with_multi_logs(self, crash_context, log_files_content):
        """Enhanced ownership analysis using multiple log files and all components"""
        # Perform multi-log incident analysis first
        multi_log_analyzer = MultiLogIncidentAnalyzer()
        incident_analysis = multi_log_analyzer.analyze_log_directory(log_files_content)
        
        # Check if any genuine crash was found
        if not incident_analysis.get('summary', {}).get('crash_found', False):
            # Return early with "no crash found" result - structure it like a normal ownership result
            return {
                'primary_ownership': 'No Crash Detected',
                'component_category': 'no_crash',
                'confidence': 'N/A',
                'hypothesis': 'No genuine crash detected - logs show routine system operations only',
                'escalation_team': 'None - No crash to analyze',
                'evidence_summary': [],
                'detailed_evidence': {},
                'recommendation': incident_analysis.get('summary', {}).get('recommendation', 'No crash evidence found in uploaded logs'),
                'scoring_details': [],
                'analysis_note': 'Enhanced Phase 2 detected no genuine crash events. Activities like "starting coredump processing" are routine operations.',
                'pattern_source': 'Ultra-strict crash detection',
                'multi_log_analysis': incident_analysis,
                'contextual_insights': ['No crash detected - routine system operations only'],
                'crash_found': False,
                'analysis_type': 'No crash - routine system operations detected'
            }
        
        # Combine all log content for ownership analysis
        combined_content = '\n'.join(log_files_content.values())
        
        # Perform enhanced ownership analysis with all components
        ownership_result = self.analyze_ownership(crash_context, combined_content)
        
        # Enhance ownership analysis with multi-log insights
        enhanced_result = self._enhance_with_incident_analysis(ownership_result, incident_analysis)
        
        return enhanced_result
    
    def analyze_ownership(self, crash_context, log_content):
        """Enhanced ownership determination supporting all RDK components"""
        combined_content = log_content
        
        # Reset specific plugin tracking for this analysis
        self._specific_plugins_in_crash = []
        
        # Initialize evidence structure for all component categories
        ownership_evidence = {}
        for category in self.ownership_patterns.keys():
            ownership_evidence[category] = {
                'high_confidence': [],
                'medium_confidence': [],
                'low_confidence': []
            }
        
        # Analyze patterns for each component category
        for category, patterns in self.ownership_patterns.items():
            for pattern_data in patterns:
                if len(pattern_data) == 3:
                    pattern, description, confidence_tier = pattern_data
                else:
                    pattern, description = pattern_data
                    confidence_tier = 'low'
                
                try:
                    matches = re.findall(pattern, combined_content, re.IGNORECASE)
                    if matches:
                        ownership_evidence[category][f'{confidence_tier}_confidence'].append({
                            'pattern': description,
                            'matches': len(matches),
                            'evidence_text': matches[:2],
                            'regex_pattern': pattern,
                            'category': category  # Add category to evidence
                        })
                except re.error:
                    # Skip invalid patterns
                    continue
        
        # Enhanced crash context analysis
        if crash_context:
            self._analyze_crash_context(crash_context, ownership_evidence)
        
        # Special analysis for component activation crashes
        activation_results = self._analyze_component_activation_crashes(log_content)
        for result in activation_results:
            category = result['category']
            if category in ownership_evidence:
                ownership_evidence[category]['high_confidence'].append({
                    'pattern': f'{result["component_name"]} activation crash',
                    'matches': 1,
                    'evidence_text': [result['crash_detail']],
                    'regex_pattern': 'activation_crash_analysis',
                    'category': category  # Add category to evidence
                })
        
        # Determine ownership with enhanced multi-component support
        ownership_result = self._determine_enhanced_ownership(ownership_evidence)
        
        return ownership_result
    
    def _analyze_crash_context(self, crash_context, ownership_evidence):
        """Enhanced crash context analysis for all components"""
        crashed_process = crash_context.get('crashed_process', '').lower()
        
        # Component process mapping
        process_mappings = {
            'thunder_core': ['wpeframework', 'thunder'],
            'thunder_plugins': ['plugin', '.so'],
            'hal_managers': ['dsmgrmain', 'mfrmgrmain', 'sysmgrmain', 'cecmain', 'irmgrmain'],
            'iarm_components': ['iarmdaemonmain', 'iarm'],
            'media_components': ['rmfstreamer', 'audiocapturemgr'],
            'security_components': ['secmanager', 'authservice'],
            'network_components': ['tr69hostif', 'xdiscovery', 'bluetoothd'],
            'system_services': ['deepslepmgrmain', 'parodus', 'lighttpd', 'dnsmasq', 'ledmgr']
        }
        
        for category, process_indicators in process_mappings.items():
            if any(indicator in crashed_process for indicator in process_indicators):
                confidence = 'high' if category in ['thunder_core', 'thunder_plugins', 'security_components'] else 'medium'
                ownership_evidence[category][f'{confidence}_confidence'].append({
                    'pattern': f'Crashed process name indicates {category.replace("_", " ")}',
                    'matches': 1,
                    'evidence_text': [crashed_process],
                    'regex_pattern': 'process_name_analysis',
                    'category': category  # Add category to evidence
                })
    
    def _analyze_component_activation_crashes(self, log_content):
        """Analyze component activation crashes for all RDK components"""
        results = []
        lines = log_content.split('\n')
        
        # Component activation patterns
        activation_patterns = [
            # Thunder plugins
            (r'Activated\s+plugin\s+\[([^\]]+)\]', 'thunder_plugins', 'plugin'),
            # HAL manager startups
            (r'([ds|mfr|sys|cec|ir]MgrMain)\[\d+\].*Start', 'hal_managers', 'manager'),
            # IARM connections
            (r'IARM.*member\s+name\s*=\s*([^\s,]+)', 'iarm_components', 'member'),
            # Security components
            (r'SecManager.*(?:Initialize|Start)', 'security_components', 'security'),
            # Media components
            (r'rmfStreamer.*(?:initialize|start)', 'media_components', 'media')
        ]
        
        for i, line in enumerate(lines):
            for pattern, category, comp_type in activation_patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    component_name = match.group(1) if match.groups() else comp_type
                    
                    # Check next few lines for crashes
                    next_lines = lines[i+1:i+5]
                    crash_patterns = [
                        'pure virtual method called',
                        'terminate called',
                        'Signal received',
                        'segmentation fault',
                        'abort()',
                        'crash',
                        'failed'
                    ]
                    
                    for next_line in next_lines:
                        for crash_pattern in crash_patterns:
                            if crash_pattern.lower() in next_line.lower():
                                results.append({
                                    'category': category,
                                    'component_name': component_name,
                                    'crash_detail': f"{component_name} {crash_pattern}",
                                    'activation_line': line.strip(),
                                    'crash_line': next_line.strip()
                                })
                                break
        
        return results
    
    def _determine_enhanced_ownership(self, ownership_evidence):
        """Enhanced ownership determination supporting all RDK components"""
        # Calculate weighted scores for each category
        category_scores = {}
        
        for category, evidence in ownership_evidence.items():
            high_count = len(evidence['high_confidence'])
            medium_count = len(evidence['medium_confidence'])
            low_count = len(evidence['low_confidence'])
            
            # Base scoring: high=3, medium=1, low=0.3
            base_score = (high_count * 3) + (medium_count * 1) + (low_count * 0.3)
            
            # Apply component weight
            component_weight = self.component_weights.get(category, 1.0)
            weighted_score = base_score * component_weight
            
            category_scores[category] = {
                'base_score': base_score,
                'weighted_score': weighted_score,
                'high_evidence': high_count,
                'medium_evidence': medium_count,
                'low_evidence': low_count,
                'component_weight': component_weight
            }
        
        # Find the category with highest weighted score
        if not any(scores['base_score'] > 0 for scores in category_scores.values()):
            return self._create_ownership_result(
                'Unknown Component', 'Low',
                'No clear ownership indicators found in the crash logs',
                ownership_evidence, category_scores
            )
        
        best_category = max(category_scores.keys(), 
                          key=lambda x: category_scores[x]['weighted_score'])
        best_score_data = category_scores[best_category]
        
        # Enhanced confidence determination
        confidence = self._calculate_enhanced_confidence(best_score_data, category_scores)
        
        # Generate enhanced hypothesis
        hypothesis = self._generate_enhanced_hypothesis(best_category, ownership_evidence[best_category], confidence, best_score_data)
        
        return self._create_ownership_result(best_category, confidence, hypothesis, ownership_evidence, category_scores)
    
    def _calculate_enhanced_confidence(self, best_score_data, all_scores):
        """Calculate confidence with enhanced logic for all components"""
        high_evidence = best_score_data['high_evidence']
        medium_evidence = best_score_data['medium_evidence']
        weighted_score = best_score_data['weighted_score']
        
        # Check for competing evidence
        competing_scores = [score['weighted_score'] for score in all_scores.values() 
                          if score != best_score_data and score['weighted_score'] > 0]
        max_competing = max(competing_scores) if competing_scores else 0
        
        # High confidence criteria
        if (high_evidence >= 2 or 
            (high_evidence >= 1 and medium_evidence >= 2) or
            (weighted_score > max_competing * 2 and high_evidence >= 1)):
            return 'High'
        
        # Medium confidence criteria  
        elif (high_evidence >= 1 or 
              medium_evidence >= 3 or
              (weighted_score > max_competing * 1.5 and medium_evidence >= 1)):
            return 'Medium'
        
        # Low confidence
        else:
            return 'Low'
    
    def _generate_enhanced_hypothesis(self, owner_category, owner_evidence, confidence_level, score_data):
        """Generate enhanced hypothesis for all component types"""
        confidence_qualifier = {
            'High': 'Strong evidence indicates',
            'Medium': 'Evidence suggests', 
            'Low': 'Limited evidence points to'
        }.get(confidence_level, 'Evidence suggests')
        
        # Collect all evidence patterns
        all_patterns = []
        for evidence_list in owner_evidence.values():
            all_patterns.extend([item['pattern'] for item in evidence_list])
        
        # Component-specific hypothesis generation
        hypothesis_map = {
            'thunder_core': self._generate_thunder_core_hypothesis,
            'thunder_plugins': self._generate_thunder_plugin_hypothesis,
            'hal_managers': self._generate_hal_hypothesis,
            'iarm_components': self._generate_iarm_hypothesis,
            'media_components': self._generate_media_hypothesis,
            'security_components': self._generate_security_hypothesis,
            'network_components': self._generate_network_hypothesis,
            'system_services': self._generate_system_hypothesis,
            'comrpc_layer': self._generate_comrpc_hypothesis
        }
        
        hypothesis_generator = hypothesis_map.get(owner_category)
        if hypothesis_generator:
            specific_hypothesis = hypothesis_generator(all_patterns, confidence_qualifier)
            
            # Add weight information for transparency
            weight_info = f" (Component priority weight: {score_data['component_weight']:.1f})"
            return specific_hypothesis + weight_info
        else:
            return f"{confidence_qualifier} {owner_category.replace('_', ' ')} issues, but specific analysis needs further investigation."
    
    def _generate_thunder_core_hypothesis(self, patterns, qualifier):
        if any('worker' in pattern.lower() or 'thread' in pattern.lower() for pattern in patterns):
            return f"{qualifier} Thunder framework threading or worker pool issues in core components."
        elif any('assert' in pattern.lower() for pattern in patterns):
            return f"{qualifier} Thunder framework assertion failure or critical core component failure."
        else:
            return f"{qualifier} Thunder core framework components are involved, likely requiring framework team investigation."
    
    def _generate_thunder_plugin_hypothesis(self, patterns, qualifier):
        # Check for specific plugins that were found in crash analysis
        specific_plugins = getattr(self, '_specific_plugins_in_crash', [])
        
        if specific_plugins:
            plugin_list = ', '.join(set(specific_plugins))
            if any('activation' in pattern.lower() for pattern in patterns):
                return f'{qualifier} specific Thunder plugin crash during initialization: {plugin_list}. Plugin activation sequence triggered the crash.'
            elif any('virtual' in pattern.lower() for pattern in patterns):
                return f'{qualifier} plugin-related pure virtual method call error in {plugin_list}, indicating object lifecycle issues during plugin initialization.'
            else:
                return f'{qualifier} Thunder plugin issues in {plugin_list} requiring plugin development team analysis.'
        else:
            # Fallback to generic analysis
            if any('activation' in pattern.lower() for pattern in patterns):
                return f'{qualifier} Thunder plugin crash during activation or initialization phase.'
            elif any('virtual' in pattern.lower() for pattern in patterns):
                return f'{qualifier} plugin-related pure virtual method call error, indicating object lifecycle issues.'
            else:
                return f'{qualifier} Thunder plugin-related issues requiring plugin development team analysis.'
    
    def _generate_hal_hypothesis(self, patterns, qualifier):
        if any(term in ' '.join(patterns).lower() for term in ['display', 'video', 'ds']):
            return f"{qualifier} HAL display/video subsystem issues requiring display HAL team investigation."
        elif any(term in ' '.join(patterns).lower() for term in ['power', 'thermal', 'sys']):
            return f"{qualifier} HAL power/system management issues requiring system HAL team investigation."
        else:
            return f"{qualifier} HAL (Hardware Abstraction Layer) issues requiring appropriate HAL team investigation."
    
    def _generate_iarm_hypothesis(self, patterns, qualifier):
        if any('connection' in pattern.lower() or 'bus' in pattern.lower() for pattern in patterns):
            return f"{qualifier} IARM bus communication breakdown, potentially affecting multiple components."
        else:
            return f"{qualifier} IARM inter-process communication issues requiring IARM bus team investigation."
    
    def _generate_media_hypothesis(self, patterns, qualifier):
        if any(term in ' '.join(patterns).lower() for term in ['rmf', 'stream', 'pipeline']):
            return f"{qualifier} media streaming/RMF pipeline issues requiring media team investigation."
        elif any(term in ' '.join(patterns).lower() for term in ['audio', 'capture']):
            return f"{qualifier} audio processing/capture issues requiring audio team investigation."
        else:
            return f"{qualifier} media subsystem issues requiring media team investigation."
    
    def _generate_security_hypothesis(self, patterns, qualifier):
        if any(term in ' '.join(patterns).lower() for term in ['drm', 'license', 'widevine', 'playready']):
            return f"{qualifier} DRM/content protection issues requiring security DRM team investigation."
        elif any('auth' in pattern.lower() for pattern in patterns):
            return f"{qualifier} authentication/authorization issues requiring security team investigation."
        else:
            return f"{qualifier} security subsystem issues requiring security team investigation."
    
    def _generate_network_hypothesis(self, patterns, qualifier):
        if any('tr069' in pattern.lower() or 'tr-069' in pattern.lower() for pattern in patterns):
            return f"{qualifier} TR-069 device management issues, likely environmental or network-related."
        elif any('bluetooth' in pattern.lower() for pattern in patterns):
            return f"{qualifier} Bluetooth connectivity issues requiring bluetooth team investigation."
        else:
            return f"{qualifier} network services issues, potentially environmental or configuration-related."
    
    def _generate_system_hypothesis(self, patterns, qualifier):
        if any('sleep' in pattern.lower() or 'power' in pattern.lower() for pattern in patterns):
            return f"{qualifier} system power management issues requiring power management team investigation."
        else:
            return f"{qualifier} system services issues, often environmental or configuration-related."
    
    def _generate_comrpc_hypothesis(self, patterns, qualifier):
        return f"{qualifier} COMRPC layer communication issues or RPC boundary problems between components."
    
    def _create_ownership_result(self, owner_category, confidence_level, hypothesis, all_evidence, scores_data):
        """Create enhanced ownership analysis result"""
        # Format owner name
        owner_name = owner_category.replace('_', ' ').title()
        
        # Get escalation team
        escalation_team = self.escalation_teams.get(owner_category, 'Unknown Team')
        
        # Generate recommendation with enhanced information
        recommendation = self._generate_enhanced_recommendation(owner_category, confidence_level, scores_data)
        
        # Create detailed scoring information
        scoring_details = self._create_scoring_details(scores_data)
        
        return {
            'primary_ownership': owner_name,
            'component_category': owner_category,
            'confidence': confidence_level,
            'hypothesis': hypothesis,
            'escalation_team': escalation_team,
            'evidence_summary': self._summarize_evidence(all_evidence),
            'detailed_evidence': all_evidence,
            'recommendation': recommendation,
            'scoring_details': scoring_details,
            'analysis_note': 'Enhanced Phase 2 uses dynamic patterns and supports all RDK components. Confidence reflects pattern strength and component priority weighting.',
            'pattern_source': 'Dynamic pattern management system'
        }
    
    def _generate_enhanced_recommendation(self, owner_category, confidence, scores_data):
        """Generate enhanced escalation recommendation"""
        escalation_team = self.escalation_teams.get(owner_category, 'Unknown Team')
        
        if confidence == 'High':
            return f"Escalate to {escalation_team} - High confidence determination"
        elif confidence == 'Medium':
            return f"Escalate to {escalation_team} with additional context - Medium confidence"
        else:
            return f"Further investigation recommended before escalating to {escalation_team} - Low confidence"
    
    def _create_scoring_details(self, scores_data):
        """Create detailed scoring information for transparency"""
        scoring_details = []
        
        # Sort by weighted score
        sorted_scores = sorted(scores_data.items(), 
                             key=lambda x: x[1]['weighted_score'], 
                             reverse=True)
        
        for category, score_info in sorted_scores:
            if score_info['base_score'] > 0:
                scoring_details.append({
                    'component': category.replace('_', ' ').title(),
                    'base_score': score_info['base_score'],
                    'weight': score_info['component_weight'],
                    'weighted_score': score_info['weighted_score'],
                    'high_evidence': score_info['high_evidence'],
                    'medium_evidence': score_info['medium_evidence'],
                    'low_evidence': score_info['low_evidence']
                })
        
        return scoring_details
    
    def _summarize_evidence(self, evidence_data):
        """Enhanced evidence summary for all components"""
        evidence = []
        for category, data in evidence_data.items():
            total_evidence = (len(data.get('high_confidence', [])) + 
                            len(data.get('medium_confidence', [])) + 
                            len(data.get('low_confidence', [])))
            if total_evidence > 0:
                all_patterns = []
                for confidence_level in ['high_confidence', 'medium_confidence', 'low_confidence']:
                    patterns = [item['pattern'] for item in data.get(confidence_level, [])]
                    all_patterns.extend(patterns)
                
                evidence.append({
                    'component': category.replace('_', ' ').title(),
                    'category': category.replace('_', ' ').title(),
                    'category_key': category,
                    'high_confidence_count': len(data.get('high_confidence', [])),
                    'medium_confidence_count': len(data.get('medium_confidence', [])),
                    'low_confidence_count': len(data.get('low_confidence', [])),
                    'key_patterns': all_patterns[:3],
                    'escalation_team': self.escalation_teams.get(category, 'Unknown Team')
                })
        
        return sorted(evidence, 
                     key=lambda x: (x['high_confidence_count'], x['medium_confidence_count'], x['low_confidence_count']),
                     reverse=True)
    
    def _enhance_with_incident_analysis(self, ownership_result, incident_analysis):
        """Enhance ownership determination with multi-log insights"""
        ownership_result['multi_log_analysis'] = incident_analysis
        
        # Add contextual insights
        ownership_result['contextual_insights'] = self._generate_contextual_insights(
            incident_analysis, ownership_result['primary_ownership']
        )
        
        return ownership_result
    
    def _generate_contextual_insights(self, incident_analysis, primary_ownership):
        """Generate insights based on incident patterns and ownership"""
        insights = []
        
        # Analysis based on crash correlation patterns
        crash_count = incident_analysis['summary'].get('crash_found', 0) 
        if crash_count > 1:
            insights.append(f"Multiple crash instances detected ({crash_count}), indicating potential systematic issue")
        
        # Component-specific insights
        if 'hal' in primary_ownership.lower():
            insights.append("HAL issues often require hardware/driver investigation")
        elif 'iarm' in primary_ownership.lower():
            insights.append("IARM issues may cause cascading failures in dependent components")
        elif 'media' in primary_ownership.lower():
            insights.append("Media issues may be related to codec, pipeline, or streaming infrastructure")
        elif 'security' in primary_ownership.lower():
            insights.append("Security issues require careful handling due to DRM/authentication implications")
        
        return insights if insights else ["Standard component analysis completed"]
