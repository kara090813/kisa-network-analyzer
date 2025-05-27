# ================================
# examples/test_configs.py
# 테스트용 설정 생성 스크립트

def generate_test_configs():
    """테스트용 다양한 설정 파일 생성"""
    
    configs = {
        # 모든 취약점이 포함된 최악의 시나리오
        "worst_case_cisco.cfg": """
version 12.4
hostname WorstRouter
enable password cisco
username admin password admin
snmp-server community public RW
snmp-server community private RW
ip http server
service finger
service tcp-small-servers
service udp-small-servers
cdp run
ip source-route
ip domain-lookup
line vty 0 4
 password 123
 transport input all
 no exec-timeout
line con 0
 no exec-timeout
line aux 0
 password aux
end
        """,
        
        # 일부 취약점만 있는 중간 시나리오
        "medium_case_cisco.cfg": """
version 15.1
service password-encryption
hostname MediumRouter
enable secret $1$mERr$9cTjUIlM1MHmBpJl6bYKj1
snmp-server community custom_read RO
ip http server
no service finger
no service tcp-small-servers
no service udp-small-servers
no cdp run
no ip source-route
access-list 10 permit 192.168.1.100
line vty 0 4
 password complex_password
 access-class 10 in
 transport input ssh
 exec-timeout 5 0
end
        """,
        
        # 완벽한 보안 설정
        "perfect_case_cisco.cfg": """
version 15.1
service timestamps debug datetime msec localtime show-timezone
service timestamps log datetime msec localtime show-timezone
service password-encryption
security passwords min-length 8
hostname PerfectRouter
enable secret $1$mERr$9cTjUIlM1MHmBpJl6bYKj1
no snmp-server
no ip http server
no ip http secure-server
no service finger
no service tcp-small-servers
no service udp-small-servers
no service pad
no cdp run
no ip source-route
no ip domain-lookup
ntp server 0.pool.ntp.org
logging buffered 16384 informational
logging host 192.168.1.100
ip ssh version 2
access-list 10 permit 192.168.1.100
access-list 10 deny any log
line con 0
 exec-timeout 5 0
line aux 0
 no exec
 transport input none
line vty 0 4
 access-class 10 in
 exec-timeout 5 0
 login local
 transport input ssh
end
        """
    }
    
    return configs