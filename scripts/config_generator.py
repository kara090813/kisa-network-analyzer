# ================================
# scripts/config_generator.py
# -*- coding: utf-8 -*-
"""
테스트용 설정 파일 생성기
"""

import random
from typing import Dict, List


class ConfigGenerator:
    """설정 파일 생성기"""
    
    def __init__(self):
        self.cisco_commands = {
            'basic': [
                'version 15.1',
                'service timestamps debug datetime msec',
                'service timestamps log datetime msec',
                'hostname {hostname}',
                'boot-start-marker',
                'boot-end-marker'
            ],
            'vulnerable': [
                'enable password {weak_password}',
                'username admin password {weak_password}',
                'snmp-server community public RO',
                'snmp-server community private RW',
                'ip http server',
                'service finger',
                'service tcp-small-servers',
                'service udp-small-servers',
                'cdp run',
                'ip source-route',
                'ip domain-lookup'
            ],
            'secure': [
                'enable secret $1$mERr$9cTjUIlM1MHmBpJl6bYKj1',
                'service password-encryption',
                'security passwords min-length 8',
                'no snmp-server',
                'no ip http server',
                'no service finger',
                'no service tcp-small-servers',
                'no service udp-small-servers',
                'no cdp run',
                'no ip source-route',
                'no ip domain-lookup',
                'ip ssh version 2'
            ]
        }
        
        self.weak_passwords = ['cisco', 'admin', 'password', '123456', 'cisco123']
        self.hostnames = ['Router1', 'Switch1', 'Gateway1', 'Core1', 'Distribution1']
    
    def generate_cisco_config(self, vulnerability_level: str = 'medium') -> str:
        """Cisco 설정 생성"""
        config_lines = []
        
        # 기본 설정
        hostname = random.choice(self.hostnames)
        for cmd in self.cisco_commands['basic']:
            config_lines.append(cmd.format(hostname=hostname))
        
        config_lines.append('!')
        
        # 취약점 레벨에 따른 설정
        if vulnerability_level == 'high':
            # 모든 취약점 포함
            weak_password = random.choice(self.weak_passwords)
            for cmd in self.cisco_commands['vulnerable']:
                config_lines.append(cmd.format(weak_password=weak_password))
        
        elif vulnerability_level == 'low':
            # 보안 설정 적용
            config_lines.extend(self.cisco_commands['secure'])
        
        else:  # medium
            # 일부 취약점만 포함
            weak_password = random.choice(self.weak_passwords)
            vulnerable_cmds = random.sample(self.cisco_commands['vulnerable'], 3)
            secure_cmds = random.sample(self.cisco_commands['secure'], 5)
            
            for cmd in vulnerable_cmds:
                config_lines.append(cmd.format(weak_password=weak_password))
            
            config_lines.append('!')
            config_lines.extend(secure_cmds)
        
        # 인터페이스 설정
        config_lines.extend([
            '!',
            'interface FastEthernet0/0',
            ' ip address 192.168.1.1 255.255.255.0',
            ' no shutdown',
            '!',
            'interface FastEthernet0/1',
            ' shutdown',
            '!'
        ])
        
        # VTY 설정
        if vulnerability_level == 'high':
            config_lines.extend([
                'line vty 0 4',
                f' password {random.choice(self.weak_passwords)}',
                ' login',
                ' transport input all'
            ])
        else:
            config_lines.extend([
                'access-list 10 permit 192.168.1.100',
                'line vty 0 4',
                ' access-class 10 in',
                ' login local',
                ' transport input ssh',
                ' exec-timeout 5 0'
            ])
        
        config_lines.extend(['!', 'end'])
        
        return '\n'.join(config_lines)
    
    def generate_test_suite(self) -> Dict[str, str]:
        """테스트 스위트 생성"""
        return {
            'high_vulnerability': self.generate_cisco_config('high'),
            'medium_vulnerability': self.generate_cisco_config('medium'),
            'low_vulnerability': self.generate_cisco_config('low'),
            'minimal_config': 'version 15.1\nhostname MinimalRouter\nend',
            'empty_config': '',
            'comment_only': '! This is a comment\n! Another comment'
        }


def main():
    """메인 함수"""
    generator = ConfigGenerator()
    test_configs = generator.generate_test_suite()
    
    for name, config in test_configs.items():
        filename = f"generated_{name}.cfg"
        with open(filename, 'w') as f:
            f.write(config)
        print(f"Generated: {filename}")


if __name__ == "__main__":
    main()