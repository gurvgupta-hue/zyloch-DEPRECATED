import re
from typing import Dict, List, Any
from scanner_core.policies.docker.base_checker import BaseDockerSecurityChecker
from scanner_core.models.violation import DockerSecurityViolation
from scanner_core.helpers.docker_helper import DockerfileInstruction
from scanner_core.constants.security_constants import DockerSecurityConstants


class MiningDetectionChecker(BaseDockerSecurityChecker):
    """Check for cryptocurrency mining and malware indicators"""
    
    # Common mining software patterns. Generic finance/blockchain nouns like
    # "monero", "ethereum", "bitcoin" were deliberately removed - they match
    # legitimate blockchain-app dependencies (e.g. `npm install ethereumjs-tx`)
    # with no mining involved. Keep only names/domains that are specific to
    # mining software or mining-pool infrastructure.
    MINING_PATTERNS = [
        "minerd", "xmrig", "cpuminer", "ccminer", "ethminer", "claymore",
        "phoenix-miner", "t-rex", "gminer", "lolminer", "nanominer", "nbminer",
        "teamredminer", "cryptodredge", "z-enemy", "bminer", "excavator",
        "mining-pool", "stratum+tcp", "wallet-address", "pool.minergate",
        "nanopool", "f2pool", "antpool", "slushpool", "mining.com"
    ]
    
    def check(self, contexts: List[Dict[str, Any]]) -> List[DockerSecurityViolation]:
        """Check for mining/malware indicators in Docker files"""
        self.reset_violations()
        
        for context in contexts:
            if context.get('file_type') == "Dockerfile":
                self.check_dockerfile(context.get('file_path'), context.get('instruction_objects', []))
            elif context.get('file_type') == "docker-compose":
                self.check_docker_compose(context)
        
        return self.violations
    
    def check_dockerfile(self, dockerfile_path: str, instructions: List[DockerfileInstruction]) -> None:
        """Check Dockerfile instructions for mining indicators"""
        
        for instruction in instructions:
            if instruction.instruction.lower() in ["run", "cmd", "entrypoint"]:
                self._check_command_instruction(dockerfile_path, instruction)
            elif instruction.instruction.lower() == "add":
                self._check_add_instruction(dockerfile_path, instruction)
    
    def check_docker_compose(self, context: Dict[str, Any]) -> None:
        """Check docker-compose for mining indicators"""
        parsed_data = context.get('parsed_data', {})
        
        if 'services' in parsed_data:
            for service_name, service_config in parsed_data['services'].items():
                if 'command' in service_config:
                    command = str(service_config['command'])
                    if self._contains_mining_pattern(command):
                        self._add_mining_violation(
                            context.get('file_path'),
                            None,
                            f"Service '{service_name}' command contains mining/malware indicators: {command}",
                            service_name
                        )
    
    def _check_command_instruction(self, dockerfile_path: str, instruction: DockerfileInstruction) -> None:
        """Check RUN, CMD, ENTRYPOINT instructions for mining patterns"""
        
        command_text = instruction.args.lower()
        
        if self._contains_mining_pattern(command_text):
            self._add_mining_violation(
                dockerfile_path,
                instruction,
                f"Command contains mining/malware indicators: {instruction.args}"
            )
    
    def _check_add_instruction(self, dockerfile_path: str, instruction: DockerfileInstruction) -> None:
        """Check ADD instruction for suspicious URLs"""
        
        args = instruction.args.lower()
        
        # Check for downloading from suspicious domains
        suspicious_domains = ["mining-pool.com", "xmrig.com", "minergate.com"]
        for domain in suspicious_domains:
            if domain in args:
                self._add_mining_violation(
                    dockerfile_path,
                    instruction,
                    f"ADD instruction downloads from suspicious domain: {domain}"
                )
                break
    
    def _contains_mining_pattern(self, text: str) -> bool:
        """Check if text contains any mining-related patterns"""
        text_lower = text.lower()
        
        for pattern in self.MINING_PATTERNS:
            if pattern in text_lower:
                return True
        
        # Check for wallet-like patterns (long hex strings), but only when the
        # surrounding text also mentions mining/wallet context - a bare
        # 40+ char hex string on its own is extremely common as a checksum
        # (sha1sum, git commit hash) and is not itself a mining indicator.
        wallet_pattern = r'\b[a-fA-F0-9]{40,}\b'
        wallet_context_keywords = ('wallet', 'mining', 'miner', 'pool', 'stratum', 'hashrate')
        if re.search(wallet_pattern, text) and any(kw in text_lower for kw in wallet_context_keywords):
            return True

        # Check for stratum protocol patterns
        if 'stratum+tcp://' in text_lower or 'stratum+ssl://' in text_lower:
            return True
        
        return False
    
    def _add_mining_violation(self, resource_name: str, instruction: DockerfileInstruction,
                              message: str, service_name: str = None) -> None:
        """Add a mining/malware detection violation"""
        
        cve_id = "DOCKER-SEC-021"
        
        line_number = instruction.line_number if instruction else 0
        instruction_text = str(instruction) if instruction else "docker-compose configuration"
        
        self.add_violation(
            cve_id=cve_id,
            severity=DockerSecurityConstants.SEVERITY_CRITICAL,
            resource={
                'file_path': resource_name,
                'file_type': 'Dockerfile' if not service_name else 'docker-compose',
                'line_number': line_number
            },
            key_path=instruction_text,
            message=message,
            service_name=service_name,
            checker="MiningDetectionChecker"
        )