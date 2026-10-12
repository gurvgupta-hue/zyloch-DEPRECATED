import re
import yaml
import json
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from models.violation import DockerFileContext


class LineTrackedDict(dict):
    """A plain dict that also remembers the source line it was parsed from.

    The line is kept as an attribute (not a dict key) so normal dict
    operations - .items(), .get(), len(), etc. - behave exactly like a
    regular dict and are never polluted by a stray '__line__' entry.
    """
    __line__ = 0


class _LineTrackingLoader(yaml.SafeLoader):
    """SafeLoader variant that stamps every mapping with its source line.

    Each parsed mapping becomes a LineTrackedDict carrying the 1-indexed
    line number where it starts, so checkers operating on docker-compose
    YAML (which has no per-instruction structure like a Dockerfile) can
    still report a real line number instead of 0.

    SafeConstructor.construct_yaml_map builds the dict it eventually
    returns as a plain `{}` up front (to support self-referencing YAML),
    then fills it in afterwards - overriding construct_mapping alone
    would have no effect since its result is only used to .update() that
    pre-created plain dict. The map constructor itself must be replaced
    so the pre-created object is a LineTrackedDict.
    """

    def _construct_yaml_map_with_line(self, node):
        data = LineTrackedDict()
        data.__line__ = node.start_mark.line + 1
        yield data
        value = self.construct_mapping(node)
        data.update(value)


_LineTrackingLoader.add_constructor(
    'tag:yaml.org,2002:map',
    _LineTrackingLoader._construct_yaml_map_with_line
)


class DockerfileInstruction:
    """Represents a single instruction in a Dockerfile"""
    
    def __init__(self, instruction: str, args: str, line_number: int, raw_line: str):
        """
        Initialize a Dockerfile instruction.
        
        Args:
            instruction: The instruction name (e.g., 'FROM', 'RUN', 'ENV')
            args: The instruction arguments
            line_number: Line number in the file
            raw_line: The raw line content
        """
        self.instruction = instruction.upper()
        self.args = args.strip()
        self.line_number = line_number
        self.raw_line = raw_line.strip()
    
    def __str__(self):
        return f"{self.instruction} {self.args}"
    
    def __repr__(self):
        return f"DockerfileInstruction(instruction='{self.instruction}', args='{self.args}', line_number={self.line_number})"


class DockerHelper:
    """Helper class for Docker file parsing and analysis"""
    
    def __init__(self):
        """Initialize Docker helper"""
        self.dockerfile_instruction_pattern = re.compile(
            r'^\s*([A-Z][A-Z_]*)\s+(.*)$', re.MULTILINE
        )
        self.env_var_pattern = re.compile(r'(\w+)=([^\s]+)')
        self.port_pattern = re.compile(r'(\d+)(?:/(\w+))?')
    
    def parse_dockerfile(self, file_path: str) -> Dict[str, Any]:
        """
        Parse a Dockerfile and return structured context.
        
        Args:
            file_path: Path to the Dockerfile
            
        Returns:
            Dictionary with parsed information including DockerfileInstruction objects
        """
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Keep blank lines so instruction line numbers match the source file.
        lines = content.splitlines()
        
        # Parse all instructions
        instructions = {}
        instruction_objects = []
        
        for i, line in enumerate(lines, 1):
            line_clean = line.strip()
            if line_clean and not line_clean.startswith('#'):
                match = self.dockerfile_instruction_pattern.match(line_clean)
                if match:
                    instruction = match.group(1).upper()
                    args = match.group(2).strip()
                    
                    # Create instruction object
                    inst_obj = DockerfileInstruction(instruction, args, i, line_clean)
                    instruction_objects.append(inst_obj)
                    
                    # Group by instruction type for compatibility
                    if instruction not in instructions:
                        instructions[instruction] = []
                    instructions[instruction].append({
                        'line': i,
                        'args': args,
                        'raw_line': line_clean
                    })
        
        return {
            'file_path': file_path,
            'file_type': "Dockerfile",
            'content': content,
            'lines': lines,
            'parsed_instructions': instructions,
            'instruction_objects': instruction_objects
        }
    
    def parse_docker_compose(self, file_path: str) -> Dict[str, Any]:
        """
        Parse a docker-compose.yml file and return structured context.
        
        Args:
            file_path: Path to the docker-compose.yml file
            
        Returns:
            Dictionary with parsed information
        """
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        try:
            parsed_yaml = yaml.load(content, Loader=_LineTrackingLoader)
        except yaml.YAMLError as e:
            # If YAML parsing fails, create context with error
            parsed_yaml = {"error": str(e)}
        
        return {
            'file_path': file_path,
            'file_type': "docker-compose",
            'content': content,
            'lines': content.strip().split('\n'),
            'parsed_data': parsed_yaml,
            'instruction_objects': []  # Not applicable for docker-compose
        }
    
    def get_dockerfile_instructions(self, context: Dict[str, Any], instruction_type: str) -> List[Dict[str, Any]]:
        """
        Get all instances of a specific Dockerfile instruction.
        
        Args:
            context: Docker file context dictionary
            instruction_type: Type of instruction (e.g., 'FROM', 'RUN', 'USER')
            
        Returns:
            List of instruction occurrences
        """
        if context.get('file_type') != "Dockerfile":
            return []
        
        return context.get('parsed_instructions', {}).get(instruction_type.upper(), [])
    
    def get_compose_services(self, context: DockerFileContext) -> Dict[str, Any]:
        """
        Get all services from a docker-compose file.
        
        Args:
            context: Docker compose file context
            
        Returns:
            Dictionary of services
        """
        if context.file_type != "docker-compose":
            return {}
        
        if "error" in context.parsed_instructions:
            return {}
        
        return context.parsed_instructions.get("services", {})
    
    def extract_ports_from_expose(self, expose_arg: str) -> List[int]:
        """
        Extract port numbers from EXPOSE instruction argument.
        
        Args:
            expose_arg: Argument string from EXPOSE instruction
            
        Returns:
            List of port numbers
        """
        ports = []
        for port_match in self.port_pattern.finditer(expose_arg):
            port_num = int(port_match.group(1))
            ports.append(port_num)
        return ports
    
    def extract_env_vars(self, env_arg: str) -> Dict[str, str]:
        """
        Extract environment variables from ENV instruction.
        
        Args:
            env_arg: Argument string from ENV instruction
            
        Returns:
            Dictionary of environment variables
        """
        env_vars = {}
        
        # Handle both formats: ENV KEY=value and ENV KEY value
        if '=' in env_arg:
            # KEY=value format
            for match in self.env_var_pattern.finditer(env_arg):
                key = match.group(1)
                value = match.group(2)
                env_vars[key] = value
        else:
            # KEY value format (space separated)
            parts = env_arg.split()
            if len(parts) >= 2:
                key = parts[0]
                value = ' '.join(parts[1:])
                env_vars[key] = value
        
        return env_vars
    
    def is_running_as_root(self, context: DockerFileContext) -> bool:
        """
        Check if container is configured to run as root user.
        
        Args:
            context: Docker file context
            
        Returns:
            True if running as root
        """
        if context.file_type == "Dockerfile":
            user_instructions = self.get_dockerfile_instructions(context, "USER")
            if not user_instructions:
                return True  # No USER instruction means running as root
            
            # Check the last USER instruction
            last_user = user_instructions[-1]['args']
            return last_user.strip() in ['0', 'root']
        
        elif context.file_type == "docker-compose":
            services = self.get_compose_services(context)
            for service_name, service_config in services.items():
                user = service_config.get('user', 'root')
                if user in ['0', 'root']:
                    return True
        
        return False
    
    def get_base_image(self, context: DockerFileContext) -> Optional[str]:
        """
        Get the base image from Dockerfile FROM instruction.
        
        Args:
            context: Docker file context
            
        Returns:
            Base image name or None
        """
        if context.file_type != "Dockerfile":
            return None
        
        from_instructions = self.get_dockerfile_instructions(context, "FROM")
        if from_instructions:
            # Return the last FROM instruction (in case of multi-stage builds)
            return from_instructions[-1]['args'].split()[0]
        
        return None
    
    def extract_capabilities(self, cap_add_args: str) -> List[str]:
        """
        Extract capabilities from --cap-add arguments.
        
        Args:
            cap_add_args: Capability arguments string
            
        Returns:
            List of capabilities
        """
        # Remove quotes and split by comma or space
        caps = cap_add_args.strip('\'"').replace(',', ' ').split()
        return [cap.strip() for cap in caps if cap.strip()]
    
    def find_secrets_in_line(self, line: str, secret_patterns: List[str]) -> List[str]:
        """
        Find potential secrets in a line based on patterns.
        
        Args:
            line: Line to analyze
            secret_patterns: List of patterns to search for
            
        Returns:
            List of found secret patterns
        """
        found_secrets = []
        line_upper = line.upper()
        
        for pattern in secret_patterns:
            if pattern.upper() in line_upper:
                found_secrets.append(pattern)
        
        return found_secrets
    
    def is_privileged_port(self, port: int) -> bool:
        """
        Check if port is a privileged port (0-1023).
        
        Args:
            port: Port number
            
        Returns:
            True if privileged port
        """
        return 0 <= port <= 1023
    
    def get_line_by_number(self, context: DockerFileContext, line_number: int) -> str:
        """
        Get specific line content by line number.
        
        Args:
            context: Docker file context
            line_number: Line number (1-indexed)
            
        Returns:
            Line content or empty string
        """
        if 1 <= line_number <= len(context.lines):
            return context.lines[line_number - 1]
        return ""
    
    def safe_get(self, data: Dict[str, Any], key: str, default: Any = None) -> Any:
        """
        Safely get value from dictionary with default.
        
        Args:
            data: Dictionary to search
            key: Key to find
            default: Default value if key not found
            
        Returns:
            Value or default
        """
        return data.get(key, default)