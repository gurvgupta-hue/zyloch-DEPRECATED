from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Callable

import yaml


@dataclass
class ValidationMessage:
    line: int
    column: int
    message: str
    severity: str
    rule: str
    error_type: Optional[str] = None
    context: Optional[str] = None


@dataclass
class ValidationResult:
    valid: bool
    errors: List[ValidationMessage]
    warnings: List[ValidationMessage]
    suggestions: List[str]
    file_info: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid,
            "errors": [vars(msg) for msg in self.errors],
            "warnings": [vars(msg) for msg in self.warnings],
            "suggestions": list(self.suggestions),
            "file_info": dict(self.file_info),
        }


class ErrorValidator:
    """
    Generic error validation and filtering system.
    Provides a rule-based approach to filter false positives and prioritize errors.
    """
    
    def __init__(self, lines: List[str]):
        self.lines = lines
        self.static_errors_by_line: Dict[int, List[ValidationMessage]] = {}
        self.parser_errors_by_line: Dict[int, List[ValidationMessage]] = {}
    
    def register_static_error(self, error: ValidationMessage) -> None:
        """Register a static analysis error."""
        if error.line not in self.static_errors_by_line:
            self.static_errors_by_line[error.line] = []
        self.static_errors_by_line[error.line].append(error)
    
    def register_parser_error(self, error: ValidationMessage) -> None:
        """Register a parser-generated error."""
        if error.line not in self.parser_errors_by_line:
            self.parser_errors_by_line[error.line] = []
        self.parser_errors_by_line[error.line].append(error)
    
    def _get_line_content(self, line_no: int) -> str:
        """Get the content of a line (1-indexed)."""
        if 0 < line_no <= len(self.lines):
            return self.lines[line_no - 1]
        return ""
    
    def _is_false_positive(self, error: ValidationMessage, error_source: str = "parser") -> bool:
        """
        Generic false positive detection using rule-based validation.
        
        Args:
            error: The error to validate
            error_source: "parser" or "static"
            
        Returns:
            True if the error is a false positive, False otherwise
        """
        line_content = self._get_line_content(error.line)
        if not line_content:
            return False
        
        stripped = line_content.strip()
        msg_lower = error.message.lower()
        
        # Rule 1: If error says "missing colon" but line has a colon, it's likely a false positive
        # (cascading error from previous line)
        if "missing" in msg_lower and "colon" in msg_lower:
            if ":" in stripped:
                # Check if there's a static error on a previous line that explains this
                # Look back up to 5 lines for a related static error
                for prev_line in range(max(1, error.line - 5), error.line):
                    if prev_line in self.static_errors_by_line:
                        for static_err in self.static_errors_by_line[prev_line]:
                            if "missing" in static_err.message.lower() and "colon" in static_err.message.lower():
                                return True  # This is a cascading error, static error is the real one
                return True  # Line has colon, so this is a false positive
        
        # Rule 2: If error mentions a character that doesn't exist on the line, it's suspicious
        # Extract character mentions from error message
        char_patterns = [
            (r"missing ['\"]([^'\"]+)['\"]", "missing character"),
            (r"unexpected ['\"]([^'\"]+)['\"]", "unexpected character"),
            (r"found ['\"]([^'\"]+)['\"]", "found character"),
        ]
        
        for pattern, error_type in char_patterns:
            match = re.search(pattern, error.message, re.IGNORECASE)
            if match:
                char = match.group(1)
                # If the mentioned character doesn't exist on the line, might be a false positive
                if char not in stripped and error_type == "missing character":
                    # But only if there's no similar error on previous lines
                    has_related_error = False
                    for prev_line in range(max(1, error.line - 3), error.line):
                        if prev_line in self.static_errors_by_line:
                            for static_err in self.static_errors_by_line[prev_line]:
                                if char in static_err.message.lower():
                                    has_related_error = True
                                    break
                    if not has_related_error:
                        return True
        
        # Rule 3: If static error exists for same line with similar message, prioritize static
        if error_source == "parser" and error.line in self.static_errors_by_line:
            for static_err in self.static_errors_by_line[error.line]:
                # Check if messages are similar (same error type)
                static_msg_lower = static_err.message.lower()
                common_keywords = ['colon', 'missing', 'syntax', 'indentation', 'unterminated', 'invalid', 'quote']
                if any(keyword in static_msg_lower and keyword in msg_lower for keyword in common_keywords):
                    # Static error takes precedence
                    return True
        
        # Rule 4: Check if error location makes sense given line content
        if error.column > 0:
            # If column is way beyond line length, it's suspicious
            if error.column > len(line_content) + 10:
                return True
        
        return False
    
    def validate_and_merge_errors(self) -> List[ValidationMessage]:
        """
        Validate all registered errors, filter false positives, and merge static and parser errors.
        Static errors take precedence over parser errors when they conflict.
        
        Returns:
            List of validated, deduplicated errors
        """
        validated_errors: List[ValidationMessage] = []
        seen_error_keys = set()
        
        # First, add all static errors (they have higher priority)
        for line_no in sorted(self.static_errors_by_line.keys()):
            for error in self.static_errors_by_line[line_no]:
                error_key = (error.line, error.column, error.message.lower().strip())
                if error_key not in seen_error_keys:
                    validated_errors.append(error)
                    seen_error_keys.add(error_key)
        
        # Then, add parser errors that pass validation
        for line_no in sorted(self.parser_errors_by_line.keys()):
            for error in self.parser_errors_by_line[line_no]:
                error_key = (error.line, error.column, error.message.lower().strip())
                
                # Skip if already seen (static error takes precedence)
                if error_key in seen_error_keys:
                    continue
                
                # Check for false positives
                if not self._is_false_positive(error, error_source="parser"):
                    validated_errors.append(error)
                    seen_error_keys.add(error_key)
        
        # Sort by line and column
        validated_errors.sort(key=lambda e: (e.line, e.column))
        
        return validated_errors


def generate_json_suggestions(error: json.JSONDecodeError) -> List[str]:
   
    suggestions: List[str] = []
    error_msg = str(error.msg).lower()

    if "expecting ',' delimiter" in error_msg:
        suggestions.append("Add a comma (,) between object properties or array elements.")
    elif "expecting ':' delimiter" in error_msg:
        suggestions.append("Add a colon (:) after the property name.")
    elif "expecting property name" in error_msg:
        suggestions.append("Property names must be enclosed in double quotes.")
    elif "unterminated string" in error_msg:
        suggestions.append("Close the string with matching quotes.")
    elif "expecting value" in error_msg:
        suggestions.append("Provide a valid value (string, number, boolean, null, object, or array).")
    elif "extra data" in error_msg:
        suggestions.append("Remove extra characters after the JSON ends.")
    else:
        suggestions.append("Check JSON syntax - ensure proper use of braces, brackets, and quotes.")

    return suggestions


def _format_yaml_error_message(error: yaml.YAMLError) -> str:
    
    error_str = str(error)
    error_lines = error_str.replace('\\n', '\n').split('\n')
    error_candidates = []
    
    for line in error_lines:
        line = line.strip()
        if not line:
            continue
        
        if line.startswith('in "') and 'line' in line and 'column' in line:
            continue
        
        if line in ['^', '...'] or line.startswith('...'):
            continue
        
        if line.startswith('    ') and not any(keyword in line.lower() for keyword in ['error', 'expected', 'found', 'missing', 'invalid']):
            continue
        
        if 'found unexpected' in line.lower():
            if 'end of stream' in line.lower():
                error_candidates.insert(0, "Unterminated string or block - missing closing quote or bracket")
            else:
                unexpected_match = re.search(r"found unexpected '([^']+)'", line, re.IGNORECASE)
                if unexpected_match:
                    unexpected = unexpected_match.group(1)
                    error_candidates.insert(0, f"Unexpected character: '{unexpected}'")
                else:
                    error_candidates.append("Unexpected syntax error")
        elif 'could not find expected' in line.lower():
            if "':'" in line or "':' in line":
                error_candidates.insert(0, "Missing colon (:) after key")
            elif "'" in line:
                expected_match = re.search(r"could not find expected '([^']+)'", line, re.IGNORECASE)
                if expected_match:
                    expected = expected_match.group(1)
                    error_candidates.insert(0, f"Missing expected '{expected}'")
                else:
                    error_candidates.append("Syntax error: missing expected character")
            else:
                error_candidates.append("Syntax error: missing expected character")
        elif 'mapping values are not allowed here' in line.lower():
            error_candidates.insert(0, "Indentation error - mapping values not allowed at this position")
        elif 'expected' in line.lower() and '<block end>' in line.lower():
            error_candidates.insert(0, "Indentation error - expected block to end")
        elif 'duplicated key' in line.lower():
            key_match = re.search(r"duplicated key: '([^']+)'", line, re.IGNORECASE)
            if key_match:
                key_name = key_match.group(1)
                error_candidates.insert(0, f"Duplicate key: '{key_name}'")
            else:
                error_candidates.append("Duplicate key detected")
        elif 'while scanning' in line.lower():
            if 'quoted scalar' in line.lower():
                error_candidates.append("Unterminated quoted string - missing closing quote")
            elif 'simple key' in line.lower():
                error_candidates.append("Syntax error in key-value pair")
            else:
                error_candidates.append("Syntax error while scanning")
        elif 'while parsing' in line.lower():
            if 'block mapping' in line.lower():
                error_candidates.append("Indentation or structure error in mapping")
            elif 'block sequence' in line.lower():
                error_candidates.append("Indentation or structure error in list")
            else:
                error_candidates.append("Parsing error - check indentation and structure")
        elif 'found character' in line.lower() and '\\t' in line.lower():
            error_candidates.insert(0, "Tab character found - YAML requires spaces for indentation")
        else:
            if (len(line) < 200 and 
                not line.startswith('in "') and 
                not line.startswith('...') and
                not line.startswith('    ') and  
                any(keyword in line.lower() for keyword in ['error', 'expected', 'found', 'missing', 'invalid', 'syntax'])):
                error_candidates.append(line)
    
    
    if error_candidates:
        return error_candidates[0]
    
    
    for line in error_lines:
        line = line.strip()
        if (line and 
            not line.startswith('in "') and 
            not line.startswith('...') and 
            len(line) < 200 and
            not line.startswith('    ')):
            return line
    
    return "YAML syntax error"


def generate_yaml_suggestions(error: yaml.YAMLError) -> List[str]:
    """Generate helpful suggestions for YAML errors."""
    suggestions: List[str] = []
    error_msg = str(error).lower()

    if "could not find expected ':'" in error_msg:
        suggestions.append("Add a colon (:) after the key name.")
    elif "found character '\\t'" in error_msg:
        suggestions.append("Replace tabs with spaces - YAML does not allow tab characters.")
    elif "mapping values are not allowed here" in error_msg:
        suggestions.append("Check indentation - ensure proper alignment of keys and values.")
    elif "expected <block end>" in error_msg:
        suggestions.append("Check indentation consistency throughout the file.")
    elif "duplicated key" in error_msg:
        suggestions.append("Remove or rename duplicate keys in the same mapping.")
    elif "while scanning a quoted scalar" in error_msg:
        suggestions.append("Close quoted strings properly or escape quotes within strings.")
    else:
        suggestions.append("Check YAML syntax - ensure proper indentation and structure.")

    return suggestions


def check_yaml_warnings(content: str) -> List[ValidationMessage]:
    """Detect non-fatal YAML formatting issues such as tabs or trailing spaces."""
    warnings: List[ValidationMessage] = []
    lines = content.splitlines()

    for idx, line in enumerate(lines, 1):
        if line.rstrip() != line:
            warnings.append(
                ValidationMessage(
                    line=idx,
                    column=len(line),
                    message="Trailing whitespace detected.",
                    severity="warning",
                    rule="formatting",
                    error_type=None,
                    context=line,
                )
            )
        if "\t" in line:
            warnings.append(
                ValidationMessage(
                    line=idx,
                    column=line.index("\t") + 1,
                    message="Tab character detected - YAML requires spaces for indentation.",
                    severity="warning",
                    rule="indentation",
                    error_type=None,
                    context=line,
                )
            )

    return warnings


def _detect_json_static_errors(content: str, lines: List[str]) -> List[ValidationMessage]:
    """
    Detect static JSON errors that don't cause parse failures but are still issues.
    Examples: duplicate keys, trailing commas (in strict mode), etc.
    """
    errors: List[ValidationMessage] = []
    seen_errors = set()
    
    def add_error(line: int, col: int, message: str, context: str = None) -> None:
        error_key = (line, col, message.lower().strip())
        if error_key in seen_errors:
            return
        if context is None:
            context = lines[line - 1] if 0 < line <= len(lines) else ""
        errors.append(
            ValidationMessage(
                line=line,
                column=col,
                message=message,
                severity="error",
                rule="json_syntax",
                error_type="StaticAnalysis",
                context=context,
            )
        )
        seen_errors.add(error_key)
    
    # Check for duplicate keys in objects (JSON allows this but it's often a mistake)
    # This is a simplified check - full detection would require proper parsing
    in_string = False
    escape_next = False
    current_line = 1
    current_col = 1
    key_positions = {}  # Track potential keys and their positions
    
    for i, char in enumerate(content):
        if char == '\n':
            current_line += 1
            current_col = 1
        else:
            current_col += 1
        
        if escape_next:
            escape_next = False
            continue
        
        if char == '\\':
            escape_next = True
            continue
        
        if char == '"' and not escape_next:
            in_string = not in_string
            continue
        
        if not in_string:
            # Look for potential duplicate keys (simplified - just check for repeated quoted strings)
            if char == ':' and i > 0:
                # Look backwards for a key
                j = i - 1
                while j >= 0 and content[j] in ' \t\n':
                    j -= 1
                if j >= 0 and content[j] == '"':
                    # Found a key, check if we've seen it before in the same object scope
                    key_start = j
                    key_end = key_start + 1
                    while key_end < len(content) and content[key_end] != '"':
                        if content[key_end] == '\\':
                            key_end += 2
                        else:
                            key_end += 1
                    if key_end < len(content):
                        key = content[key_start:key_end+1]
                        line_num = content[:key_start].count('\n') + 1
                        if key in key_positions and key_positions[key] != line_num:
                            # Potential duplicate key
                            col_num = key_start - content.rfind('\n', 0, key_start)
                            add_error(line_num, col_num, f"Potential duplicate key: {key}", lines[line_num - 1] if 0 < line_num <= len(lines) else "")
                        key_positions[key] = line_num
    
    return errors


def _collect_all_json_errors(content: str, lines: List[str]) -> List[ValidationMessage]:
    """
    Comprehensive JSON error collector using sequential error recovery.
    Finds all unique errors by parsing sequentially, skipping past each found error.
    """
    errors: List[ValidationMessage] = []
    seen_errors = set()  
    
    def get_line_col(pos: int) -> tuple[int, int]:
        """Convert character position to (line, column)."""
        line_num = content[:pos].count('\n') + 1
        last_newline = content.rfind('\n', 0, pos)
        col_num = pos - last_newline if last_newline >= 0 else pos + 1
        return (line_num, col_num)
    
    def add_error(line: int, col: int, message: str, context: str = None, error_type: str = "JSONDecodeError") -> None:
        # Use a more lenient deduplication - only check line and message, not column
        # This allows multiple errors on the same line with different columns
        msg_normalized = message.lower().strip()
        # Use line and message for deduplication, but allow same message on different columns
        error_key = (line, msg_normalized)
        
        if error_key in seen_errors:
            # Check if this is a different column position for the same error
            # If so, we might want to include it if it provides more context
            existing_error = next((e for e in errors if e.line == line and e.message.lower().strip() == msg_normalized), None)
            if existing_error and existing_error.column == col:
                return  # Exact duplicate
            # If column is different, we might have multiple issues on the same line
            # Allow it but mark it differently
            error_key = (line, col, msg_normalized)
            if error_key in seen_errors:
                return
        
        if context is None:
            context = lines[line - 1] if 0 < line <= len(lines) else ""
        
        errors.append(
            ValidationMessage(
                line=line,
                column=col,
                message=message,
                severity="error",
                rule="json_syntax",
                error_type=error_type,
                context=context,
            )
        )
        seen_errors.add(error_key)
        seen_errors.add((line, msg_normalized))  # Also add the line+message key
    
    primary_error_line = None
    primary_error_col = None
    primary_error_pos = None
    
    # First, try to parse the entire content to get the primary error
    try:
        json.loads(content)
        # If parsing succeeds, check for common issues that might not cause parse errors
        # but are still problems (e.g., duplicate keys in objects)
        return _detect_json_static_errors(content, lines)
    except json.JSONDecodeError as primary_error:
        line_num = primary_error.lineno
        col_num = primary_error.colno
        error_msg = str(primary_error.msg)
        context_line = lines[line_num - 1] if 0 < line_num <= len(lines) else ""
        add_error(line_num, col_num, error_msg, context_line)
        
        
        primary_error_line = line_num
        primary_error_col = col_num
        primary_error_pos = primary_error.pos if hasattr(primary_error, 'pos') else 0
    
    
    line_starts = []
    pos = 0
    for line in lines:
        line_starts.append(pos)
        pos += len(line) + 1
    
    
    checked_positions = set()
    current_pos = 0
    max_errors = 200  
    error_count = len(errors)
    
    
    content_stripped = content.lstrip()
    if content_stripped.startswith(('{', '[')) and primary_error_pos is not None:
        current_pos = max(1, primary_error_pos + 1)
    
    while current_pos < len(content) and error_count < max_errors:
        if current_pos in checked_positions:
            current_pos += 1
            continue
        
        checked_positions.add(current_pos)
        
        remaining = content[current_pos:]
        if not remaining.strip():
            break
        
        
        remaining_stripped = remaining.lstrip()
        if not remaining_stripped:
            break
        
        first_char = remaining_stripped[0]
        whitespace_offset = len(remaining) - len(remaining_stripped)
        
        
        try:
            if first_char == '{':
                test_content = remaining_stripped
                wrapper_offset = 0
            elif first_char == '[':
                test_content = remaining_stripped
                wrapper_offset = 0
            elif first_char == '"':
                test_content = '{' + remaining_stripped + '}'
                wrapper_offset = 1  
            else:
                test_content = '{' + remaining_stripped + '}'
                wrapper_offset = 1
            
            json.loads(test_content)
            next_line = content.find('\n', current_pos)
            if next_line != -1:
                current_pos = next_line + 1
            else:
                break
        except json.JSONDecodeError as e:
            if e.pos < wrapper_offset:  
                current_pos += 1
                continue
        
            actual_pos = current_pos + whitespace_offset + (e.pos - wrapper_offset)
            if actual_pos >= len(content):
                break
            
            line_num, col_num = get_line_col(actual_pos)
            error_msg = str(e.msg)
            
            
            if primary_error_line is not None and primary_error_col is not None:
                if (line_num, col_num) == (primary_error_line, primary_error_col):
                    current_pos += 1
                    continue
            
            context_line = lines[line_num - 1] if 0 < line_num <= len(lines) else ""
            add_error(line_num, col_num, error_msg, context_line)
            error_count = len(errors)
            next_pos = actual_pos + 1
            for i in range(actual_pos + 1, min(actual_pos + 200, len(content))):
                if content[i] in ',:{}[]\n':
                    next_pos = i + 1
                    break
            
            current_pos = next_pos
    
    # Also run static error detection to catch issues that don't cause parse errors
    static_errors = _detect_json_static_errors(content, lines)
    for static_err in static_errors:
        # Add static errors that aren't duplicates
        error_key = (static_err.line, static_err.message.lower().strip())
        line_msg_key = (static_err.line, static_err.message.lower().strip())
        if line_msg_key not in seen_errors:
            errors.append(static_err)
            seen_errors.add((static_err.line, static_err.column, static_err.message.lower().strip()))
            seen_errors.add(line_msg_key)
    
    errors.sort(key=lambda e: (e.line, e.column))
    
    return errors


def validate_json_content(content: str) -> ValidationResult:
    lines = content.splitlines()
    size_bytes = len(content.encode("utf-8"))
    line_count = len(lines)

    try:
        json.loads(content)
        return ValidationResult(
            valid=True,
            errors=[],
            warnings=[],
            suggestions=[],
            file_info={"size_bytes": size_bytes, "lines": line_count, "format": "json"},
        )
    except json.JSONDecodeError as error:
        all_errors = _collect_all_json_errors(content, lines)
        
        if len(all_errors) == 1:
            context_line = lines[error.lineno - 1] if 0 < error.lineno <= len(lines) else ""
            all_errors[0].context = context_line
        
        suggestions = generate_json_suggestions(error)
        
        return ValidationResult(
            valid=False,
            errors=all_errors,
            warnings=[],
            suggestions=suggestions,
            file_info={"size_bytes": size_bytes, "lines": line_count, "format": "json"},
        )
    except Exception as error:  
        validation_error = ValidationMessage(
            line=0,
            column=0,
            message=f"Unexpected error: {error}",
            severity="error",
            rule="unknown",
            error_type=type(error).__name__,
        )
        return ValidationResult(
            valid=False,
            errors=[validation_error],
            warnings=[],
            suggestions=[],
            file_info={"size_bytes": size_bytes, "lines": line_count, "format": "json"},
        )


def _detect_static_yaml_errors(content: str, lines: List[str]) -> List[ValidationMessage]:
    errors: List[ValidationMessage] = []
    seen_errors = set()
    
    def add_error(line_no: int, col_no: int, message: str, error_type: str = "StaticAnalysis") -> None:
        msg_normalized = message.lower().strip()
        error_key = (line_no, col_no, msg_normalized)
        
        if error_key in seen_errors:
            return
        
        context_line = lines[line_no - 1] if 0 < line_no <= len(lines) else ""
        errors.append(
            ValidationMessage(
                line=line_no,
                column=col_no,
                message=message,
                severity="error",
                rule="yaml_syntax",
                error_type=error_type,
                context=context_line,
            )
        )
        seen_errors.add(error_key)
    
    indent_stack = [0]
    
    for line_idx, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        
       
        indent = len(line) - len(line.lstrip())
        
        single_quotes = stripped.count("'") - stripped.count("\\'")
        double_quotes = stripped.count('"') - stripped.count('\\"')
        
        # Check for unterminated double-quoted strings
        if ':' in stripped and '"' in stripped:
            colon_pos = stripped.find(':')
            value_part = stripped[colon_pos + 1:].strip()
            if value_part.startswith('"'):
                # Count unescaped quotes in the value part
                quote_count = 0
                escaped = False
                for char in value_part:
                    if escaped:
                        escaped = False
                        continue
                    if char == '\\':
                        escaped = True
                        continue
                    if char == '"':
                        quote_count += 1
                
                # If odd number of quotes, string is not closed on this line
                if quote_count % 2 == 1:
                    # Check if quote closes on a later line - be more strict about this
                    found_close = False
                    # Look ahead to see if there's a closing quote on the next few lines
                    # But be careful - it should be at the same or greater indentation level
                    for next_idx in range(line_idx + 1, min(line_idx + 10, len(lines) + 1)):
                        if next_idx <= len(lines):
                            next_line = lines[next_idx - 1]
                            next_stripped = next_line.strip()
                            next_indent = len(next_line) - len(next_line.lstrip())
                            
                            # If we hit a line with same or less indentation that's not empty/comment,
                            # and it's not a continuation of the value, the string is not closed
                            if next_stripped and not next_stripped.startswith('#') and next_indent <= indent:
                                # Check if it looks like a new key-value pair (has colon at same level)
                                if ':' in next_stripped and next_indent == indent:
                                    # This is a new key, string is definitely not closed
                                    break
                                # If it's a list item or other structure, string might continue
                                if next_stripped.startswith('-') and next_indent > indent:
                                    continue
                            
                            # Check if this line has a closing quote that could close our string
                            if '"' in next_line:
                                # More strict: the quote should be at a position that makes sense
                                # (not at the start of a new key, etc.)
                                quote_pos_in_line = next_line.find('"')
                                # If quote is early in the line and line looks like a value continuation, it might close
                                # But if it's part of a new key-value pair, it doesn't close our string
                                if quote_pos_in_line < len(next_line) // 2 or next_indent > indent:
                                    found_close = True
                                    break
                    
                    if not found_close:
                        quote_col = line.find('"') + 1
                        add_error(line_idx, quote_col, "Unterminated double-quoted string", "UnterminatedString")
        
        
        if ':' in stripped and "'" in stripped:
            colon_pos = stripped.find(':')
            value_part = stripped[colon_pos + 1:].strip()
            if value_part.startswith("'"):
                remaining_after_open = value_part[1:]
                if "'" not in remaining_after_open:
                    found_close = False
                    for next_idx in range(line_idx, min(line_idx + 10, len(lines))):
                        if "'" in lines[next_idx - 1]:
                            found_close = True
                            break
                    if not found_close:
                        quote_col = line.find("'") + 1
                        add_error(line_idx, quote_col, "Unterminated single-quoted string", "UnterminatedString")
        

        # Check for missing colon - only on lines that don't have colons and look like key-value pairs
        # Skip if line already has a colon (to avoid false positives)
        if ':' not in stripped and not stripped.startswith('-') and not stripped.startswith('|') and not stripped.startswith('>') and not stripped.startswith('#'):
            # More strict pattern - must look like a key followed by a value
            key_value_match = re.match(r'^([a-zA-Z_][a-zA-Z0-9_]+)\s+([^\s#\n]+(?:\s+[^\s#\n]+)*)', stripped)
            if key_value_match:
                key_name = key_value_match.group(1)
                value_part = key_value_match.group(2).strip()
                if '#' in value_part:
                    value_part = value_part.split('#')[0].strip()
                # Only flag if there's actually a value and it doesn't look like a comment or special syntax
                if value_part and not value_part.startswith('#') and not value_part.startswith('|') and not value_part.startswith('>'):
                    # Additional check: make sure this isn't just a list item continuation or other valid YAML
                    # Skip if the line looks like it might be part of a multiline value or document separator
                    if not re.match(r'^\s*\.\.\.', stripped) and not re.match(r'^\s*---', stripped):
                        key_end_pos = line.find(key_name) + len(key_name)
                        if key_end_pos > 0:
                            add_error(line_idx, key_end_pos + 1, f"Missing colon (:) after key '{key_name}'", "MissingColon")
                    
                    
                    first_word = value_part.split()[0] if value_part.split() else ""
                    if first_word and re.match(r'^(tru|fals|truue|falsse)$', first_word, re.IGNORECASE):
                        value_start = line.find(first_word)
                        if value_start >= 0:
                            add_error(line_idx, value_start + 1, f"Invalid boolean value: '{first_word}' (should be 'true' or 'false')", "InvalidBoolean")
        
        
        bool_pattern = r':\s*(tru[^e]|fals[^e]|truue|falsse|True[^,]|False[^,])\s*(?:#|$)'
        bool_match = re.search(bool_pattern, stripped, re.IGNORECASE)
        if not bool_match:
            
            if re.search(r':\s*(tru|fals)\s*(?:#|$)', stripped, re.IGNORECASE):
                bool_match = re.search(r':\s*(tru|fals)\s*(?:#|$)', stripped, re.IGNORECASE)
        if bool_match:
            col_pos = stripped.find(bool_match.group(0)) + 1
            invalid_val = bool_match.group(1).strip()
            add_error(line_idx, col_pos + indent, f"Invalid boolean value: '{invalid_val}' (should be 'true' or 'false')", "InvalidBoolean")
        
        
        if stripped.endswith(',') and not stripped.endswith(',,'):
            
            if stripped.startswith('-') or '[' in stripped or (':' in stripped and stripped.split(':')[-1].strip().endswith(',')):
                comma_pos = len(line.rstrip())
                add_error(line_idx, comma_pos, "Trailing comma not allowed in YAML", "TrailingComma")
        
        
        number_pattern = r':\s*(\d+\.\d+\.\d+)'
        number_match = re.search(number_pattern, stripped)
        if number_match:
            col_pos = stripped.find(number_match.group(0)) + 1
            add_error(line_idx, col_pos + indent, f"Invalid number format: '{number_match.group(1)}'", "InvalidNumber")
        
        
        if '{' in stripped and ':' in stripped:
            json_style_pattern = r'\{[^}]*:[^}]*\}'
            if re.search(json_style_pattern, stripped):
                brace_pos = stripped.find('{')
                add_error(line_idx, brace_pos + indent, "JSON-style object syntax not recommended in YAML", "JsonStyleSyntax")
        
        
        open_braces = stripped.count('{') - stripped.count('}')
        open_brackets = stripped.count('[') - stripped.count(']')
        if open_braces > 0 or open_brackets > 0:
            total_open = open_braces + open_brackets
            found_close = False
            for next_idx in range(line_idx, min(line_idx + 20, len(lines))):
                next_line = lines[next_idx - 1]
                total_open -= (next_line.count('}') + next_line.count(']'))
                if total_open <= 0:
                    found_close = True
                    break
            if not found_close:
                brace_pos = max(stripped.find('{'), stripped.find('['))
                if brace_pos >= 0:
                    add_error(line_idx, brace_pos + indent, "Unterminated braces or brackets", "UnterminatedBrackets")
        
        
        if stripped.startswith('-') and indent > 0:
            prev_indent = indent_stack[-1] if indent_stack else 0
            if indent > prev_indent + 2:  
                dash_pos = line.find('-')
                add_error(line_idx, dash_pos + 1, "Invalid list item indentation", "InvalidIndentation")
        
        if ':' in stripped and not stripped.startswith('-'):
            key_match = re.match(r'^(\s*)([a-zA-Z_][a-zA-Z0-9_]*)\s*:', stripped)
            if key_match:
                key_name = key_match.group(2)
                key_indent = len(key_match.group(1))
                
                for prev_idx in range(max(1, line_idx - 50), line_idx):
                    prev_line = lines[prev_idx - 1]
                    prev_stripped = prev_line.strip()
                    if ':' in prev_stripped and not prev_stripped.startswith('-'):
                        prev_key_match = re.match(r'^(\s*)([a-zA-Z_][a-zA-Z0-9_]*)\s*:', prev_line)
                        if prev_key_match:
                            prev_key_name = prev_key_match.group(2)
                            prev_key_indent = len(prev_key_match.group(1))
                            if prev_key_name == key_name and prev_key_indent == key_indent:
                                
                                same_scope = True
                                for between_idx in range(prev_idx + 1, line_idx):
                                    between_line = lines[between_idx - 1]
                                    between_indent = len(between_line) - len(between_line.lstrip())
                                    if between_indent < key_indent:
                                        same_scope = False
                                        break
                                if same_scope:
                                    add_error(line_idx, key_match.end() - len(key_name), f"Duplicate key: '{key_name}'", "DuplicateKey")
                                    break
        
        
        if stripped.startswith('-') and line_idx > 1:
           
            prev_line = lines[line_idx - 2]
            prev_indent = len(prev_line) - len(prev_line.lstrip())
            if indent > prev_indent + 2:
                
                if not prev_line.strip().startswith('-'):
                    
                    dash_pos = line.find('-')
                    add_error(line_idx, dash_pos + 1, "Invalid list item indentation - list item nested under non-list parent", "InvalidIndentation")
            
            
            if ':' in stripped and not stripped.startswith('- -') and not stripped.startswith('-  -'):
               
                if prev_line.strip().startswith('-') and indent == prev_indent:
                    
                    if re.match(r'^\s*-\s*-\s*', line):
                        pass  
                    elif re.match(r'^\s*-\s*$', prev_line.strip()):
                        
                        dash_pos = line.find('-')
                        add_error(line_idx, dash_pos + 1, "Invalid nested list structure - consider using '- - item' format", "InvalidListStructure")
        
        
        
        double_colon_pattern = r':\s*[^:]+:\s*$'
        if re.search(double_colon_pattern, stripped):
            colon_pos = stripped.rfind(':')
            if colon_pos > 0:
                add_error(line_idx, colon_pos + indent + 1, "Extra colon (:) after value", "ExtraColon")
        
        
        if '>' in stripped or '|' in stripped:
            if ':' in stripped:
                colon_pos = stripped.find(':')
                after_colon = stripped[colon_pos + 1:].strip()
                if after_colon.startswith('>') or after_colon.startswith('|'):
                    found_next = False
                    for next_idx in range(line_idx, min(line_idx + 10, len(lines))):
                        next_line = lines[next_idx - 1]
                        if next_line.strip() and not next_line.strip().startswith('#'):
                            found_next = True
                            next_indent = len(next_line) - len(next_line.lstrip())
                            if next_indent <= indent:
                                if next_line.strip() and ':' in next_line and not next_line.strip().startswith('-'):
                                    multiline_content_lines = 0
                                    for check_idx in range(line_idx + 1, next_idx):
                                        check_line = lines[check_idx - 1]
                                        check_indent = len(check_line) - len(check_line.lstrip())
                                        if check_indent > indent:
                                            multiline_content_lines += 1
                                    if multiline_content_lines == 0:
                                        add_error(line_idx, colon_pos + indent + 2, "Multiline string block appears empty or improperly formatted", "InvalidMultiline")
                            break
                    if not found_next:
                        multiline_indicator = '>' if '>' in after_colon else '|'
                        indicator_pos = line.find(multiline_indicator) + 1
                        add_error(line_idx, indicator_pos, "Multiline string block may not be properly terminated", "UnterminatedMultiline")
        
        
        if stripped and not stripped.startswith('#'):
            while indent_stack and indent < indent_stack[-1]:
                indent_stack.pop()
            if not indent_stack or indent > indent_stack[-1]:
                indent_stack.append(indent)
            elif indent == indent_stack[-1]:
                pass  
    
    return errors


def _collect_all_yaml_errors(content: str, lines: List[str]) -> List[ValidationMessage]:
    """
    Collect all YAML errors using the generic ErrorValidator system.
    This provides a systematic approach to error detection, validation, and false positive filtering.
    """
    # Initialize the generic error validator
    validator = ErrorValidator(lines)
    
    # Step 1: Collect static analysis errors (higher priority)
    static_errors = _detect_static_yaml_errors(content, lines)
    for err in static_errors:
        validator.register_static_error(err)
    
    # Step 2: Collect parser errors (will be validated and filtered)
    try:
        list(yaml.compose_all(content))
        # If parsing succeeds, return only static errors
        return validator.validate_and_merge_errors()
    except yaml.YAMLError as first_error:
        problem_mark = getattr(first_error, "problem_mark", None)
        if problem_mark:
            line_no = problem_mark.line + 1
            col_no = problem_mark.column + 1
        else:
            line_no = 1
            col_no = 1
        
        formatted_message = _format_yaml_error_message(first_error)
        context_line = lines[line_no - 1] if 0 < line_no <= len(lines) else ""
        
        parser_error = ValidationMessage(
            line=line_no,
            column=col_no,
            message=formatted_message,
            severity="error",
            rule="yaml_syntax",
            error_type=type(first_error).__name__,
            context=context_line,
        )
        validator.register_parser_error(parser_error)
    
    
    if "---" in content:
        documents = content.split("---")
        line_offset = 0
        
        for doc_idx, doc_content in enumerate(documents):
            if not doc_content.strip():
                line_offset += 1
                continue
            

            if doc_idx > 0:
                doc_content = "---" + doc_content
            
            try:
                yaml.safe_load(doc_content)
            except yaml.YAMLError as doc_error:
                doc_problem_mark = getattr(doc_error, "problem_mark", None)
                if doc_problem_mark:
                    doc_line_no = doc_problem_mark.line + 1
                    if doc_idx > 0:
                        lines_before = content[:content.find(doc_content)].count('\n')
                        actual_line_no = lines_before + doc_line_no
                    else:
                        actual_line_no = doc_line_no
                    
                    col_no = doc_problem_mark.column + 1
                    formatted_message = _format_yaml_error_message(doc_error)
                    context_line = lines[actual_line_no - 1] if 0 < actual_line_no <= len(lines) else ""
                    
                    parser_error = ValidationMessage(
                        line=actual_line_no,
                        column=col_no,
                        message=formatted_message,
                        severity="error",
                        rule="yaml_syntax",
                        error_type=type(doc_error).__name__,
                        context=context_line,
                    )
                    validator.register_parser_error(parser_error)
            
            
            line_offset += doc_content.count('\n')
    

    sections = []
    current_section = []
    section_start_line = 0
    
    for i, line in enumerate(lines):
        is_section_break = (
            line.strip() == "" or
            (line.strip() and not line.startswith(' ') and not line.startswith('\t') and ':' in line)
        )
        
        if is_section_break and current_section:
            sections.append((section_start_line, current_section))
            current_section = []
            section_start_line = i + 1
        
        if line.strip():  
            current_section.append(line)
        elif not current_section: 
            section_start_line = i + 1
    
    if current_section:
        sections.append((section_start_line, current_section))
    
    for section_start, section_lines in sections:
        if not section_lines:
            continue
        
        section_content = '\n'.join(section_lines)
        if not section_content.strip():
            continue
        
        try:
            yaml.safe_load(section_content)
        except yaml.YAMLError as section_error:
            section_mark = getattr(section_error, "problem_mark", None)
            if section_mark:
                actual_line_no = section_start + section_mark.line + 1
                actual_col_no = section_mark.column + 1
                formatted_message = _format_yaml_error_message(section_error)
                context_line = lines[actual_line_no - 1] if 0 < actual_line_no <= len(lines) else ""
                
                parser_error = ValidationMessage(
                    line=actual_line_no,
                    column=actual_col_no,
                    message=formatted_message,
                    severity="error",
                    rule="yaml_syntax",
                    error_type=type(section_error).__name__,
                    context=context_line,
                )
                validator.register_parser_error(parser_error)
    
    
    for line_idx, line in enumerate(lines[:200], 1): 
        if not line.strip() or line.strip().startswith('#'):
            continue
        
        stripped = line.strip()
        
        
        if (not stripped.startswith('-') and 
            not stripped.startswith('|') and 
            not stripped.startswith('>') and
            ':' not in stripped and 
            stripped and
            not any(c in stripped for c in ['{', '}', '[', ']'])):

            try:
                yaml.safe_load(line)
            except yaml.YAMLError as line_error:
                line_mark = getattr(line_error, "problem_mark", None)
                if line_mark:
                    actual_line_no = line_idx
                    actual_col_no = line_mark.column + 1
                    formatted_message = _format_yaml_error_message(line_error)
                    context_line = lines[actual_line_no - 1] if 0 < actual_line_no <= len(lines) else ""
                    
                    parser_error = ValidationMessage(
                        line=actual_line_no,
                        column=actual_col_no,
                        message=formatted_message,
                        severity="error",
                        rule="yaml_syntax",
                        error_type=type(line_error).__name__,
                        context=context_line,
                    )
                    validator.register_parser_error(parser_error)
    
    # Step 3: Validate, filter false positives, and merge all errors
    return validator.validate_and_merge_errors()


def validate_yaml_content(content: str) -> ValidationResult:
    
    lines = content.splitlines()
    size_bytes = len(content.encode("utf-8"))
    line_count = len(lines)

    try:
        yaml.safe_load(content)
        warnings = check_yaml_warnings(content)
        return ValidationResult(
            valid=True,
            errors=[],
            warnings=warnings,
            suggestions=[],
            file_info={
                "size_bytes": size_bytes,
                "lines": line_count,
                "format": "yaml",
                "has_multiple_documents": "---" in content,
            },
        )
    except yaml.YAMLError as error:
        all_errors = _collect_all_yaml_errors(content, lines)
        
        if len(all_errors) == 1:
            problem_mark = getattr(error, "problem_mark", None)
            if problem_mark:
                line_no = problem_mark.line + 1
                col_no = problem_mark.column + 1
            else:
                line_no = 1
                col_no = 1
            context_line = lines[line_no - 1] if 0 < line_no <= len(lines) else ""
            all_errors[0].context = context_line
        
        
        suggestions = generate_yaml_suggestions(error)
        
        warnings = check_yaml_warnings(content)
        
        return ValidationResult(
            valid=False,
            errors=all_errors,
            warnings=warnings,
            suggestions=suggestions,
            file_info={"size_bytes": size_bytes, "lines": line_count, "format": "yaml"},
        )
    except Exception as error: 
        validation_error = ValidationMessage(
            line=0,
            column=0,
            message=f"Unexpected error: {error}",
            severity="error",
            rule="unknown",
            error_type=type(error).__name__,
        )
        return ValidationResult(
            valid=False,
            errors=[validation_error],
            warnings=[],
            suggestions=[],
            file_info={"size_bytes": size_bytes, "lines": line_count, "format": "yaml"},
        )


def validate_content_by_extension(content: str, extension: str) -> ValidationResult:
    normalized_ext = extension.lower()
    if normalized_ext == "json":
        return validate_json_content(content)
    if normalized_ext in {"yaml", "yml"}:
        return validate_yaml_content(content)
    raise ValueError(f"Unsupported file extension: {extension}")
