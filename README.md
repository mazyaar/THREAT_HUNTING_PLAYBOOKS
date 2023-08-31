
# ***THREAT HUNTING PLAYBOOKS FOR MITRE TACTICS***
### _Starting your first threat hunting_

## _Reconnaissance_
***
	
## Objective: 
***Identify potential reconnaissance activity on the network***

 **Description:** _Reconnaissance is an important phase of an attack, where the attacker gathers information about the target system and network. This playbook aims to identify potential reconnaissance activity by analyzing Windows logs._

**Assumptions:** 
_The organization has a centralized logging system in place that captures Windows logs. Playbook Steps:_

***Playbook Steps:***
1. ***_Gather and Review Windows Logs_***
* _Identify the relevant log sources to be analyzed for reconnaissance activity (e.g., event logs, sysmon logs, etc.)._
* _Collect and review the logs for the past 30 days or more, depending on the organization's retention * policy._
2. ***_Identify Potential Indicators of Reconnaissance Activity._***
* _Look for unusual activity such as spikes in network traffic, failed login attempts, and unusual access patterns._
* _Use the following Windows log sources and events to identify potential indicators of reconnaissance activity:_
	* _Security Event Log: -`` Event ID 4624``: Successful logon events - ``Event ID 4625``: Failed logon events - ``Event ID 4634``: Successful logoff events -`` Event ID 4647``: User initiated logoff events_
	* _Sysmon: -`` Event ID 1``: Process creation events -`` Event ID 3``: Network connection events - ``Event ID 7``: Image load ``events - Event ID 8``: CreateRemoteThread events._
3. ***_Analyze the Indicators of Reconnaissance Activity_***
* _Review the logs for each indicator of reconnaissance activity._
*  _Identify any patterns or anomalies that could indicate potential reconnaissance activity._ 
*  _Use additional tools and techniques, such as network traffic analysis, to further investigate any suspicious activity._ 
4. ***_Determine the Scope and Impact of the Activity_***

* _Identify the scope and impact of the reconnaissance activity by analyzing the logs and any other available information._
* _Determine whether the activity is a legitimate or malicious activity._
*  _Identify any affected systems, users, or data._
5. ***_Remediate and Mitigate_***
* _Take appropriate remediation and mitigation actions based on the scope and impact of
the reconnaissance activity._
* _Develop and implement a plan to prevent similar reconnaissance activity from occurring
in the future._
6. ***_Document and Report_***
* _Document the findings, actions taken, and any recommendations for future
improvements._
* _Report the findings and recommendations to the appropriate stakeholders, such as the
incident response team and management._

* #### _The Reconnaissance Threat Hunting playbook aims to identify potential reconnaissance activity on the network by analyzing Windows logs. By following this playbook, organizations can detect and respond to reconnaissance activity in a timely manner, preventing further malicious activity on the network._
