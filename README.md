<h1 align="center"><i><b>THREAT HUNTING PLAYBOOKS FOR MITRE TACTICS 👋</h1></i></b>
<h3 align="center">Starting your first threat hunting</h3>

## _Reconnaissance_
***
	
## Objective: 
***Identify potential reconnaissance activity on the network***

 **Description:** _Reconnaissance is an important phase of an attack, where the attacker gathers information about the target system and network. This playbook aims to identify potential reconnaissance activity by analyzing Windows logs._

**Assumptions:** 
_The organization has a centralized logging system in place that captures Windows logs. Playbook Steps:_

***Playbook Steps:***

***1. _Gather and Review Windows Logs_***
* _Identify the relevant log sources to be analyzed for reconnaissance activity (e.g., event logs, sysmon logs, etc.)._
* _Collect and review the logs for the past 30 days or more, depending on the organization's retention * policy._
  
***2. _Identify Potential Indicators of Reconnaissance Activity._***
* _Look for unusual activity such as spikes in network traffic, failed login attempts, and unusual access patterns._
* _Use the following Windows log sources and events to identify potential indicators of reconnaissance activity:_
	* _Security Event Log: -`` Event ID 4624``: Successful logon events - ``Event ID 4625``: Failed logon events - ``Event ID 4634``: Successful logoff events -`` Event ID 4647``: User initiated logoff events_
	* _Sysmon: -`` Event ID 1``: Process creation events -`` Event ID 3``: Network connection events - ``Event ID 7``: Image load ``events - Event ID 8``: CreateRemoteThread events._

***3. _Analyze the Indicators of Reconnaissance Activity_***
* _Review the logs for each indicator of reconnaissance activity._
*  _Identify any patterns or anomalies that could indicate potential reconnaissance activity._ 
*  _Use additional tools and techniques, such as network traffic analysis, to further investigate any suspicious activity._
  
***4. _Determine the Scope and Impact of the Activity_***
* _Identify the scope and impact of the reconnaissance activity by analyzing the logs and any other available information._
* _Determine whether the activity is a legitimate or malicious activity._
*  _Identify any affected systems, users, or data._
  
***5. _Remediate and Mitigate_***
* _Take appropriate remediation and mitigation actions based on the scope and impact of
the reconnaissance activity._
* _Develop and implement a plan to prevent similar reconnaissance activity from occurring
in the future._

***6. _Document and Report_***
* _Document the findings, actions taken, and any recommendations for future
improvements._
* _Report the findings and recommendations to the appropriate stakeholders, such as the
incident response team and management._

* #### _The Reconnaissance Threat Hunting playbook aims to identify potential reconnaissance activity on the network by analyzing Windows logs. By following this playbook, organizations can detect and respond to reconnaissance activity in a timely manner, preventing further malicious activity on the network._
***


## _Developing Resources_
### Hypothesis:
_Attackers are developing resources for the next stage of the attack._
### Objective:
_To identify suspicious activity related to the development of resources in the network._
***Note: This playbook assumes that the organization has a baseline of normal network behavior and activity.***

***1. Data Sources***
* _Endpoint logs (e.g. Sysmon, Windows Event Logs)_
* _Network logs (e.g. NetFlow, Firewall logs)_

***2. Initial Triage***
* _Identify all hosts that have been communicating with known malicious IPs or domains._
* _Look for any unusual or suspicious domain name requests._
* _Check for any unusual or suspicious HTTP requests._
* _Look for any unusual or suspicious DNS requests._

***3. Threat Hunting Techniques***
* _Look for any unusual process or service creations._
* _Look for any unusual or suspicious registry key modifications._
* _Look for any unusual or suspicious file creations, modifications, or deletions._
* _Look for any unusual or suspicious network connections or traffic._
* _Look for any unusual or suspicious command-line arguments._

***4. Indicators of Compromise (IOCs)***
* _Malicious IP addresses or domains._
* _Unusual or suspicious process names._
* _Unusual or suspicious registry key names or values._
* _Unusual or suspicious file names, paths, or extensions._
* _Unusual or suspicious network ports or protocols._
***5. Recommended Actions***
* _Isolate any infected hosts from the network._
* _Collect any relevant forensic evidence._
* _Analyze any suspicious files, processes, or network traffic._
* _Block or blackhole any malicious IPs or domains._
* _Patch or update any vulnerable software or systems._
* _Increase monitoring and detection capabilities for future attacks._

***Note: This playbook is intended as a general guide and should be customized based on the specific
needs and environment of the organization. It is important to have a well-defined incident response
plan in place and to involve all relevant stakeholders in the threat hunting and response process.***
