from crewai import Agent

class InformationGathererAgent(Agent):
    def __init__(self, tools=None, llm=None):
        super().__init__(
            role='Web Reconnaissance Expert',
            goal='Gather comprehensive information about the target web application, including HTTP headers, SSL/TLS configuration, CMS detection, and open ports.',
            backstory='I am an experienced penetration tester with over 10 years of experience in the initial reconnaissance phase. I specialize in mapping attack surfaces and identifying underlying technologies without leaving traces. My expertise includes identifying server technologies, CMS platforms, and security misconfigurations through passive scanning techniques.',
            verbose=True,
            allow_delegation=True,
            tools=tools or [],
            llm=llm
        )

class SecurityAnalystAgent(Agent):
    def __init__(self, tools=None, llm=None):
        super().__init__(
            role='Security Vulnerability Analyst',
            goal='Analyze reconnaissance data to identify security vulnerabilities, misconfigurations, and potential attack vectors in the target web application.',
            backstory='I am a security researcher with extensive experience in vulnerability analysis and risk assessment. I have worked with major organizations to identify and mitigate web application vulnerabilities. My expertise includes analyzing HTTP headers, SSL/TLS configurations, and server technologies to identify security weaknesses that could be exploited by attackers.',
            verbose=True,
            allow_delegation=False,
            tools=tools or [],
            llm=llm
        ) 