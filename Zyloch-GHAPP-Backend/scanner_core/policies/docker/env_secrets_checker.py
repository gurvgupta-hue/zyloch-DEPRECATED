import re
from typing import Dict, List, Any
from scanner_core.policies.docker.base_checker import BaseDockerSecurityChecker
from scanner_core.models.violation import DockerSecurityViolation
from scanner_core.helpers.docker_helper import DockerfileInstruction
from scanner_core.constants.security_constants import DockerSecurityConstants


class EnvSecretsChecker(BaseDockerSecurityChecker):
    """Check for potential secrets in environment variables"""
    
    def check(self, contexts: List[Dict[str, Any]]) -> List[DockerSecurityViolation]:
        """Check for environment variable secrets in Docker files"""
        self.reset_violations()
        
        for context in contexts:
            if context.get('file_type') == "Dockerfile":
                self.check_dockerfile(context.get('file_path'), context.get('instruction_objects', []))
            elif context.get('file_type') == "docker-compose":
                self.check_docker_compose(context)
        
        return self.violations
    
    def check_dockerfile(self, dockerfile_path: str, instructions: List[DockerfileInstruction]) -> List[DockerSecurityViolation]:
        """Check for suspicious environment variable settings"""
        
        for instruction in instructions:
            if instruction.instruction.lower() == "env":
                self._check_env_instruction(dockerfile_path, instruction)
        
        return self.violations
    
    def check_docker_compose(self, context: Dict[str, Any]) -> None:
        """Check docker-compose for environment secrets"""
        parsed_data = context.get('parsed_data', {})
        
        if 'services' in parsed_data:
            for service_name, service_config in parsed_data['services'].items():
                if 'environment' in service_config:
                    env_vars = service_config['environment']
                    if isinstance(env_vars, list):
                        for env_line in env_vars:
                            if '=' in env_line:
                                key, value = env_line.split('=', 1)
                                self._check_env_var_for_secrets(context.get('file_path'), None, key, value)
                    elif isinstance(env_vars, dict):
                        for key, value in env_vars.items():
                            self._check_env_var_for_secrets(context.get('file_path'), None, key, str(value))
    
    def _check_env_instruction(self, dockerfile_path: str, instruction: DockerfileInstruction) -> None:
        """Check a single ENV instruction for potential secrets"""
        resource_name = dockerfile_path
        
        # Extract env vars from instruction
        env_vars = self._extract_env_vars_from_instruction(instruction)
        
        # Check each environment variable for potential secrets
        for env_name, env_value in env_vars:
            self._check_env_var_for_secrets(
                resource_name, instruction, env_name, env_value
            )
    
    def _extract_env_vars_from_instruction(self, instruction: DockerfileInstruction) -> List[tuple]:
        """Extract environment variable key-value pairs from ENV instruction"""
        env_vars = []
        
        args = instruction.args
        
        # Split by spaces but respect quoted values
        import shlex
        try:
            tokens = shlex.split(args)
        except ValueError:
            # If shlex fails, fall back to simple split
            tokens = args.split()
        
        for token in tokens:
            if '=' in token:
                key, value = token.split('=', 1)
                env_vars.append((key.strip(), value.strip()))
            else:
                # Handle ENV KEY value format (older format)
                if len(tokens) == 2:
                    env_vars.append((tokens[0].strip(), tokens[1].strip()))
        
        return env_vars
    
    def _check_env_var_for_secrets(self, resource_name: str, instruction: DockerfileInstruction, 
                                   env_name: str, env_value: str) -> None:
        """Check if environment variable name suggests it contains secrets"""
        
        # Check if the environment variable name suggests it contains sensitive data
        env_name_lower = env_name.lower()
        # Normalize to underscore-delimited so multi-word suspicious keys
        # (e.g. "api_key") can still match a whole run of tokens, while
        # single-word keys (e.g. "key") only match a whole token - not a
        # substring buried inside an unrelated word (e.g. "PUBLIC_KEY_PATH").
        normalized_name = f"_{re.sub(r'[^a-z0-9]+', '_', env_name_lower)}_"

        for suspicious_key in DockerSecurityConstants.SUSPICIOUS_ENV_KEYS:
            normalized_key = f"_{suspicious_key.replace('-', '_')}_"
            if normalized_key in normalized_name:
                # Check if the value looks hardcoded (not using external references)
                if self._is_likely_hardcoded_secret(env_value):
                    self._add_secret_violation(
                        resource_name, 
                        instruction, 
                        env_name, 
                        env_value, 
                        suspicious_key
                    )
                break
    
    def _is_likely_hardcoded_secret(self, value: str) -> bool:
        """Check if value appears to be a hardcoded secret"""
        value = value.strip()
        
        # Skip obvious placeholders or variable references
        placeholders = ['$', '${', '{{', 'changeme', 'placeholder', 'example', 'todo', 'fixme']
        if any(placeholder in value.lower() for placeholder in placeholders):
            return False

        # Skip filesystem paths / URLs - a *_KEY_PATH or *_CERT_PATH env var
        # points at where a (public, non-sensitive) key/cert file lives on
        # disk, it does not contain secret material itself.
        if '/' in value or value.lower().startswith(('http://', 'https://')):
            return False

        # Check for patterns that suggest hardcoded secrets
        patterns = [
            r'^[a-zA-Z0-9]{20,}$',  # Long alphanumeric strings
            r'^[a-zA-Z0-9+/]{40,}={0,2}$',  # Base64-like patterns
            r'^[a-fA-F0-9]{32,}$',  # Hex patterns (like MD5, SHA hashes)
            r'^sk_[a-zA-Z0-9_-]+$',  # Stripe-like secret keys
            r'^[a-zA-Z0-9_-]{40,}$',  # Generic long tokens
        ]
        
        for pattern in patterns:
            if re.match(pattern, value):
                return True
        
        # Check for minimum length and complexity for secrets
        if len(value) >= 8 and not value.isdigit() and not value.isalpha():
            return True
            
        return False
    
    def _add_secret_violation(self, resource_name: str, instruction: DockerfileInstruction, 
                              env_name: str, env_value: str, suspicious_pattern: str) -> None:
        """Add a hardcoded secret violation"""
        
        cve_id = "DOCKER-SEC-006"
        
        message = f"Environment variable '{env_name}' appears to contain a hardcoded secret. " \
                 f"Detected pattern: '{suspicious_pattern}'. Consider using external secret management."
        
        line_number = instruction.line_number if instruction else 0
        instruction_text = str(instruction) if instruction else f"ENV {env_name}=***"
        
        self.add_violation(
            cve_id=cve_id,
            severity=DockerSecurityConstants.SEVERITY_HIGH,
            resource={
                'file_path': resource_name,
                'file_type': 'Dockerfile',
                'line_number': line_number
            },
            key_path=instruction_text,
            message=message,
            env_var_name=env_name,
            suspicious_pattern=suspicious_pattern,
            checker="EnvSecretsChecker"
        )