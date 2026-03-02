"""
Dynamic Pattern Management System
Handles loading, updating, and managing failure patterns from JSON files
"""

import json
import os
import re
from datetime import datetime
from typing import Dict, List, Any, Optional

class DynamicPatternManager:
    """Manages dynamic pattern loading and updates from JSON files"""
    
    def __init__(self, patterns_dir: str = 'patterns'):
        self.patterns_dir = patterns_dir
        self.loaded_patterns = {}
        self.pattern_files = [
            'thunder_patterns.json',
            'hal_patterns.json', 
            'iarm_patterns.json',
            'media_patterns.json',
            'security_patterns.json',
            'network_patterns.json',
            'system_patterns.json'
        ]
        self.load_all_patterns()
    
    def load_all_patterns(self):
        """Load all pattern files into memory"""
        for pattern_file in self.pattern_files:
            file_path = os.path.join(self.patterns_dir, pattern_file)
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        component_name = pattern_file.replace('_patterns.json', '')
                        self.loaded_patterns[component_name] = data
                except Exception as e:
                    print(f"Error loading {pattern_file}: {e}")
    
    def get_all_patterns_for_analysis(self):
        """Convert dynamic patterns to format compatible with existing OwnershipAnalyzer"""
        ownership_patterns = {
            'thunder_core': [],
            'thunder_plugins': [], 
            'comrpc_layer': [],
            'hal_managers': [],
            'iarm_components': [],
            'media_components': [],
            'security_components': [],
            'network_components': [],
            'system_services': []
        }
        
        # Map components to analysis categories
        component_mapping = {
            'thunder': ['thunder_core', 'thunder_plugins', 'comrpc_layer'],
            'hal': ['hal_managers'],
            'iarm': ['iarm_components'],
            'media': ['media_components'], 
            'security': ['security_components'],
            'network': ['network_components'],
            'system': ['system_services']
        }
        
        for component_key, component_data in self.loaded_patterns.items():
            if 'patterns' not in component_data:
                continue
                
            # Determine target categories for this component
            target_categories = []
            for comp_prefix, categories in component_mapping.items():
                if comp_prefix in component_key:
                    target_categories.extend(categories)
                    break
            
            if not target_categories:
                continue
                
            # Process each pattern group in the component
            for pattern_group_name, pattern_group in component_data['patterns'].items():
                if 'patterns' not in pattern_group:
                    continue
                    
                for pattern_info in pattern_group['patterns']:
                    # Convert to legacy format for each target category
                    for target_category in target_categories:
                        if target_category == 'thunder_core' and 'thunder_core' in pattern_group_name:
                            legacy_pattern = (
                                pattern_info['pattern'], 
                                pattern_info['description'], 
                                pattern_info['confidence']
                            )
                            ownership_patterns['thunder_core'].append(legacy_pattern)
                        elif target_category == 'thunder_plugins' and 'thunder_plugin' in pattern_group_name:
                            legacy_pattern = (
                                pattern_info['pattern'],
                                pattern_info['description'],
                                pattern_info['confidence']
                            )
                            ownership_patterns['thunder_plugins'].append(legacy_pattern)
                        elif target_category == 'comrpc_layer' and 'comrpc' in pattern_group_name:
                            legacy_pattern = (
                                pattern_info['pattern'],
                                pattern_info['description'], 
                                pattern_info['confidence']
                            )
                            ownership_patterns['comrpc_layer'].append(legacy_pattern)
                        else:
                            # For new component types, add to appropriate category
                            legacy_pattern = (
                                pattern_info['pattern'],
                                pattern_info['description'],
                                pattern_info['confidence']
                            )
                            ownership_patterns[target_category].append(legacy_pattern)
        
        return ownership_patterns
    
    def add_user_pattern(self, component: str, pattern: str, description: str, 
                        confidence: str = 'medium', category: str = 'user_added'):
        """Add a new user pattern via chat interface"""
        
        if component not in self.loaded_patterns:
            return False, f"Unknown component: {component}"
        
        # Validate pattern is a valid regex
        try:
            re.compile(pattern)
        except re.error as e:
            return False, f"Invalid regex pattern: {e}"
        
        # Generate unique ID
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        pattern_id = f"user_{timestamp}"
        
        # Create pattern object
        new_pattern = {
            "id": pattern_id,
            "pattern": pattern,
            "description": description,
            "confidence": confidence,
            "category": category,
            "escalation_team": "User Defined",
            "added_by": "user_chat",
            "created_date": datetime.now().strftime("%Y-%m-%d")
        }
        
        # Add to user_patterns section
        if 'user_patterns' not in self.loaded_patterns[component]['patterns']:
            self.loaded_patterns[component]['patterns']['user_patterns'] = {
                "description": "User-contributed patterns via chat interface",
                "patterns": []
            }
        
        self.loaded_patterns[component]['patterns']['user_patterns']['patterns'].append(new_pattern)
        
        # Save to file
        return self.save_patterns(component), "Pattern added successfully"
    
    def save_patterns(self, component: str):
        """Save patterns back to JSON file"""
        try:
            file_path = os.path.join(self.patterns_dir, f"{component}_patterns.json")
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(self.loaded_patterns[component], f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"Error saving patterns for {component}: {e}")
            return False
    
    def search_patterns(self, search_term: str):
        """Search patterns by description or pattern text"""
        results = []
        
        for component_key, component_data in self.loaded_patterns.items():
            if 'patterns' not in component_data:
                continue
                
            for pattern_group_name, pattern_group in component_data['patterns'].items():
                if 'patterns' not in pattern_group:
                    continue
                    
                for pattern_info in pattern_group['patterns']:
                    if (search_term.lower() in pattern_info['description'].lower() or 
                        search_term.lower() in pattern_info['pattern'].lower()):
                        results.append({
                            'component': component_key,
                            'group': pattern_group_name,
                            'pattern': pattern_info,
                            'match_score': len([term for term in search_term.split() 
                                              if term.lower() in pattern_info['description'].lower()])
                        })
        
        # Sort by relevance
        results.sort(key=lambda x: x['match_score'], reverse=True)
        return results
    
    def get_component_stats(self):
        """Get pattern statistics for each component"""
        stats = {}
        
        for component_key, component_data in self.loaded_patterns.items():
            total_patterns = 0
            confidence_breakdown = {'high': 0, 'medium': 0, 'low': 0}
            
            if 'patterns' in component_data:
                for pattern_group_name, pattern_group in component_data['patterns'].items():
                    if 'patterns' in pattern_group:
                        for pattern_info in pattern_group['patterns']:
                            total_patterns += 1
                            confidence = pattern_info.get('confidence', 'low')
                            confidence_breakdown[confidence] = confidence_breakdown.get(confidence, 0) + 1
            
            stats[component_key] = {
                'total_patterns': total_patterns,
                'confidence_breakdown': confidence_breakdown,
                'last_updated': component_data.get('metadata', {}).get('last_updated', 'Unknown')
            }
        
        return stats
    
    def test_pattern_against_log(self, pattern: str, log_content: str):
        """Test a pattern against log content"""
        try:
            matches = re.findall(pattern, log_content, re.IGNORECASE)
            return True, len(matches), matches[:5]  # Return first 5 matches
        except re.error as e:
            return False, 0, f"Pattern error: {e}"
    
    def suggest_patterns_for_log(self, log_content: str, max_suggestions: int = 10):
        """Suggest relevant patterns based on log content analysis"""
        suggestions = []
        
        # Extract key terms from log content
        crash_terms = re.findall(r'\b(?:crash|abort|signal|segmentation|fault|error|failed)\b', 
                                log_content, re.IGNORECASE)
        component_terms = re.findall(r'\b(?:wpeframework|thunder|plugin|iarm|rmf|sec|manager|daemon)\b', 
                                   log_content, re.IGNORECASE)
        
        # Score patterns based on term matches
        for component_key, component_data in self.loaded_patterns.items():
            if 'patterns' not in component_data:
                continue
                
            for pattern_group_name, pattern_group in component_data['patterns'].items():
                if 'patterns' not in pattern_group:
                    continue
                    
                for pattern_info in pattern_group['patterns']:
                    score = 0
                    
                    # Test if pattern matches log content
                    try:
                        matches = re.findall(pattern_info['pattern'], log_content, re.IGNORECASE)
                        if matches:
                            score += len(matches) * 10  # High score for actual matches
                    except:
                        continue
                    
                    # Score based on description relevance
                    description = pattern_info['description'].lower()
                    for term in crash_terms:
                        if term.lower() in description:
                            score += 2
                    
                    for term in component_terms:
                        if term.lower() in description:
                            score += 3
                            
                    if score > 0:
                        suggestions.append({
                            'component': component_key,
                            'group': pattern_group_name,
                            'pattern': pattern_info,
                            'relevance_score': score,
                            'actual_matches': len(matches) if 'matches' in locals() else 0
                        })
        
        # Sort by relevance and return top suggestions
        suggestions.sort(key=lambda x: x['relevance_score'], reverse=True)
        return suggestions[:max_suggestions]


class ChatPatternInterface:
    """Interactive chat interface for pattern management and triaging"""
    
    def __init__(self, pattern_manager: DynamicPatternManager):
        self.pattern_manager = pattern_manager
        self.conversation_history = []
        
    def process_chat_message(self, message: str, log_content: str = None):
        """Process chat message and return appropriate response"""
        message_lower = message.lower().strip()
        
        # Add message to history
        self.conversation_history.append({
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'user_message': message,
            'type': 'user'
        })
        
        response = self._generate_response(message_lower, log_content)
        
        # Add response to history
        self.conversation_history.append({
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'bot_response': response,
            'type': 'bot'
        })
        
        return response
    
    def _generate_response(self, message: str, log_content: str = None):
        """Generate appropriate response based on message intent"""
        
        # Pattern addition requests
        if 'add pattern' in message or 'new pattern' in message:
            return self._handle_add_pattern_request(message)
        
        # Pattern search requests
        elif 'search' in message or 'find pattern' in message:
            return self._handle_search_request(message)
        
        # Component analysis requests
        elif 'analyze' in message and log_content:
            return self._handle_analyze_request(log_content)
        
        # Pattern testing requests
        elif 'test pattern' in message:
            return self._handle_test_pattern_request(message, log_content)
        
        # Help requests
        elif 'help' in message or message == '?':
            return self._generate_help_response()
        
        # Stats requests
        elif 'stats' in message or 'statistics' in message:
            return self._handle_stats_request()
        
        # Default response with suggestions
        else:
            return self._generate_suggestion_response(message, log_content)
    
    def _handle_add_pattern_request(self, message: str):
        """Handle pattern addition via natural language"""
        # Try to extract pattern details from message
        # Format: "Add [component] pattern: [regex] description: [desc]"
        
        pattern_match = re.search(r'add\s+(\w+)\s+pattern[:\s]+(.+?)(?:\s+description[:\s]+(.+))?$', message, re.IGNORECASE)
        
        if pattern_match:
            component = pattern_match.group(1)
            pattern = pattern_match.group(2).strip('"\'')
            description = pattern_match.group(3) or f"User added {component} pattern"
            
            success, result = self.pattern_manager.add_user_pattern(component, pattern, description)
            
            if success:
                return f"✅ Pattern added successfully to {component}!\nPattern: `{pattern}`\nDescription: {description}"
            else:
                return f"❌ Failed to add pattern: {result}"
        else:
            return """❓ To add a pattern, use this format:
`add [component] pattern: [regex pattern] description: [description]`

Available components: thunder, hal, iarm, media, security, network, system

Example: `add thunder pattern: WebKitPlugin.*crash description: WebKit plugin crash`"""
    
    def _handle_search_request(self, message: str):
        """Handle pattern search requests"""
        search_term = re.search(r'search\s+(?:for\s+)?(.+)', message, re.IGNORECASE)
        
        if search_term:
            term = search_term.group(1).strip('"\'')
            results = self.pattern_manager.search_patterns(term)
            
            if results:
                response = f"🔍 Found {len(results)} patterns matching '{term}':\n\n"
                for i, result in enumerate(results[:5], 1):
                    pattern_info = result['pattern']
                    response += f"{i}. **{result['component']} - {pattern_info['description']}**\n"
                    response += f"   Pattern: `{pattern_info['pattern']}`\n"
                    response += f"   Confidence: {pattern_info['confidence']}\n\n"
                
                if len(results) > 5:
                    response += f"... and {len(results) - 5} more results"
                    
                return response
            else:
                return f"❌ No patterns found matching '{term}'"
        else:
            return "❓ Please specify what to search for. Example: `search crash patterns`"
    
    def _handle_analyze_request(self, log_content: str):
        """Handle log analysis with pattern suggestions"""
        suggestions = self.pattern_manager.suggest_patterns_for_log(log_content)
        
        if suggestions:
            response = "🔍 **Analysis Results - Suggested Patterns:**\n\n"
            for i, suggestion in enumerate(suggestions[:5], 1):
                pattern_info = suggestion['pattern']
                response += f"{i}. **{suggestion['component']} - {pattern_info['description']}**\n" 
                response += f"   Confidence: {pattern_info['confidence']} | "
                response += f"   Matches: {suggestion['actual_matches']} | "
                response += f"   Team: {pattern_info.get('escalation_team', 'Unknown')}\n\n"
            
            return response
        else:
            return "❓ No matching patterns found. You might need to add new patterns for this type of issue."
    
    def _handle_test_pattern_request(self, message: str, log_content: str):
        """Handle pattern testing against log content"""
        pattern_match = re.search(r'test\s+pattern[:\s]+(.+)', message, re.IGNORECASE)
        
        if pattern_match and log_content:
            pattern = pattern_match.group(1).strip('"\'')
            success, match_count, matches = self.pattern_manager.test_pattern_against_log(pattern, log_content)
            
            if success:
                response = f"✅ **Pattern Test Results:**\n"
                response += f"Pattern: `{pattern}`\n"  
                response += f"Matches found: {match_count}\n"
                
                if matches and isinstance(matches, list):
                    response += f"Sample matches: {matches}\n"
                    
                return response
            else:
                return f"❌ Pattern test failed: {matches}"
        else:
            return "❓ To test a pattern, use: `test pattern: [your regex]` and upload log content"
    
    def _handle_stats_request(self):
        """Handle statistics request"""
        stats = self.pattern_manager.get_component_stats()
        
        response = "📊 **Pattern Statistics:**\n\n"
        total_patterns = 0
        
        for component, stat in stats.items():
            total_patterns += stat['total_patterns']
            response += f"**{component.replace('_', ' ').title()}:**\n"
            response += f"  • Total patterns: {stat['total_patterns']}\n"
            response += f"  • High confidence: {stat['confidence_breakdown']['high']}\n"
            response += f"  • Medium confidence: {stat['confidence_breakdown']['medium']}\n" 
            response += f"  • Low confidence: {stat['confidence_breakdown']['low']}\n"
            response += f"  • Last updated: {stat['last_updated']}\n\n"
        
        response += f"**Total patterns across all components: {total_patterns}**"
        return response
    
    def _generate_help_response(self):
        """Generate help message"""
        return """🤖 **WPE Crash Analysis Pattern Assistant**

**Available Commands:**
• `add [component] pattern: [regex] description: [desc]` - Add new pattern
• `search [term]` - Search existing patterns  
• `analyze` - Analyze uploaded log content for pattern matches
• `test pattern: [regex]` - Test pattern against log content
• `stats` - Show pattern statistics
• `help` - Show this help message

**Components:** thunder, hal, iarm, media, security, network, system

**Examples:**
• `add thunder pattern: VirtualDisplayManager.*crash description: VDM crash`
• `search segmentation fault`
• `test pattern: WPEFramework.*Core::.*crash`

Upload log content to enable analysis and pattern testing!"""
    
    def _generate_suggestion_response(self, message: str, log_content: str):
        """Generate response with suggestions based on message content"""
        if log_content:
            # If log content is available, suggest patterns
            suggestions = self.pattern_manager.suggest_patterns_for_log(log_content)
            if suggestions:
                return f"🤔 I see you uploaded logs. Found {len(suggestions)} relevant patterns. Type `analyze` to see detailed analysis!"
        
        # Suggest based on message keywords
        if any(term in message for term in ['crash', 'abort', 'signal']):
            return "💡 I see you're dealing with crashes. Try:\n• `search crash` to find crash-related patterns\n• `analyze` if you have log content\n• `add pattern` to create a new crash pattern"
        
        elif any(term in message for term in ['thunder', 'plugin', 'wpe']):
            return "💡 For Thunder/WPEFramework issues, try:\n• `search thunder` for Thunder patterns\n• `add thunder pattern:` to add new Thunder patterns"
        
        else:
            return "💡 Try typing `help` to see available commands, or describe your crash issue and I'll help you find relevant patterns!"
    
    def get_conversation_history(self):
        """Get formatted conversation history"""
        return self.conversation_history
    
    def clear_history(self):
        """Clear conversation history"""
        self.conversation_history = []
