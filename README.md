<h1 align="center"><i><b>THREAT HUNTING PLAYBOOKS FOR MITRE TACTICS 👋</h1></i></b>
<h3 align="center">Starting your first threat hunting</h3>

## _Reconnaissance_
### Objective: 
_Identify potential reconnaissance activity on the network_

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
* _Endpoint logs (e.g. ``Sysmon``, ``Windows Event Logs``)_
* _Network logs (e.g. ``NetFlow``, ``Firewall logs``)_

***2. Initial Triage***
* _Identify all hosts that have been communicating with known malicious ``IPs`` or ``domains``._
* _Look for any unusual or suspicious ``domain name requests``._
* _Check for any unusual or suspicious ``HTTP`` requests._
* _Look for any unusual or suspicious ``DNS`` requests._

***3. Threat Hunting Techniques***
* _Look for any unusual ``process`` or ``service`` creations._
* _Look for any unusual or suspicious ``registry key`` modifications._
* _Look for any unusual or suspicious ``file creations``, modifications, or deletions._
* _Look for any unusual or suspicious ``network connections`` or ``traffic``._
* _Look for any unusual or suspicious ``command-line`` arguments._

***4. Indicators of Compromise (``IOCs``)***
* _Malicious ``IP addresses`` or ``domains``._
* _Unusual or suspicious ``process names``._
* _Unusual or suspicious ``registry key names`` or ``values``._
* _Unusual or suspicious ``file names``, ``paths``, or ``extensions``._
* _Unusual or suspicious ``network ports`` or ``protocols``._
  
***5. Recommended Actions***
* _``Isolate`` any ``infected hosts`` from the ``network``._
* _Collect any relevant forensic evidence._
* _Analyze any ``suspicious files``, ``processes``, or ``network traffic``._
* _Block or ``blackhole`` any ``malicious IPs`` or ``domains``._
* _``Patch`` or ``update`` any ``vulnerable software or systems``._
* _Increase monitoring and detection capabilities for future attacks._

***Note: This playbook is intended as a general guide and should be customized based on the specific
needs and environment of the organization. It is important to have a well-defined incident response
plan in place and to involve all relevant stakeholders in the threat hunting and response process.***

***

## _nitial Access_
**Hypothesis:**
_Adversaries are using phishing emails to gain initial access to the network._
**Objective:**
_To detect any suspicious or malicious activity related to phishing emails and to prevent any
unauthorized access._
***Playbook:***
***1. Identify relevant logs:***
* _Email logs: ``Microsoft Exchange``, ``Office 365``, ``G Suite``, etc._
* _Web proxy logs: ``Microsoft Forefront``, ``Palo Alto Networks``, etc._
* _Network traffic logs: ``Wireshark``, ``Bro/Zeek``, etc._
* _Endpoint logs: ``Windows event logs``, ``Sysmon logs``, etc._

***2. Look for indicators of phishing emails:***
* _Check for emails sent from suspicious or ``unknown domains``._
* _Look for emails with unusual or suspicious subject lines and body content._
* _Check for emails sent from external sources, especially those not typically associated with business communication._
* _Look for emails with attachments that are uncommon or unexpected, such as ``.zip, .exe, or .dll files``._
* _Check for emails with hyperlinks that lead to unknown or suspicious websites._

***3. Check for suspicious activity on endpoints:***
* _Look for ``signs of credential harvesting``, such as ``keylogging or password stealing``._
* _Check for ``unusual`` or`` unauthorized logins``, such as ``logins from unknown`` or ``suspicious IP addresses``._
* _Check for the presence of ``suspicious files or applications``, such as those related to ``remote access`` or ``command and control`` ``(C2)`` activity._

***4. Analyze network traffic:***
* _Look for signs of network ``reconnaissance``, such as ``port scanning`` or ``ping sweeps``._
* _Check for ``unusual`` or ``unauthorized network connections``, such as connections to known ``C2`` servers._
* _Look for signs of ``lateral movement``, such as connections between ``internal`` systems that are not typically seen._

***5. Remediate any threats found:***
* _``Quarantine`` or ``delete`` suspicious ``emails``, ``attachments``, or ``files``._
* _``Block`` or ``restrict access`` to known ``malicious IP addresses`` and ``domains``._
* _``Disable`` or ``remove any suspicious`` or ``unauthorized user accounts``._
* _Ensure that all endpoints and systems are fully ``patched and updated``._

***6. Review and refine:***
* _Document all findings and actions taken._
* _Review the playbook regularly to ensure it is up-to-date and effective._
* _Continuously monitor logs and network activity to detect and respond to new threats._

***By following this Threat Hunting playbook for the Initial Access hypothesis, you can proactively detect
and respond to phishing attacks before they can do significant harm to your organization.***

***

### _Execution_

**Objective:**
_To proactively search for and identify potential malicious executions or attempted executions on
endpoints, servers, and network devices._

**Hypothesis:**
_Adversaries have gained access to the network and are attempting to execute malicious code on
endpoints or servers._

**Playbook:**

***1. Define scope: Identify the network, endpoints, and servers that are in scope for this hunt.
Ensure that the systems are up to date with the latest patches and have updated antivirus
software.***
* Gather data: Collect and analyze the following data sources to identify potential
malicious executions:
* _``Endpoint logs`` (e.g., ``Windows event logs``, ``system logs``)._
* _``Network logs`` (e.g., ``firewall logs``, ``DNS logs``)._
* _``Application logs`` (e.g., ``web server logs``, ``database logs``)._
* _``Anti-virus logs and reports``._

***2. Develop queries: Develop and run queries across the collected data sources to identify any
suspicious executions. Queries may include:***
* _Any attempts to ``execute files`` from ``suspicious locations``._
* _Any ``unauthorized executions`` of specific file types (e.g., ``.exe``, ``.bat``)._
* _Any executions with suspicious ``command-line`` ``arguments`` or ``parameters``._
* _Any executions of known ``malicious`` ``files`` or ``hashes``._

***3. Analyze results: Review the results of the queries to identify potential indicators of compromise
(IOCs). These may include:***
* _Unusual ``file paths`` or ``locations``._
* _Suspicious ``file names`` or ``extensions``._
* _Known ``malware file ``hashes``._
* _Any anomalous ``command-line`` ``parameters or arguments``._

***4. Take action: Once potential IOCs have been identified, take the following actions:***
* _Quarantine any suspicious files or systems._
* _Conduct further investigation to confirm the existence of malicious activity._
* _Update antivirus signatures and firewalls to block known malicious files and hashes._
* _If necessary, escalate the incident to the incident response team for further action._

***5. Report: Document the findings and actions taken during the hunt. Share the findings with the
appropriate stakeholders and ensure that any necessary actions are taken to prevent future
attacks.***


***By following this playbook, you can proactively identify potential malicious executions and take steps to
prevent further attacks on your network. It is important to conduct regular threat hunting exercises to
stay ahead of potential attackers.***

***

## _Persistence_

**Objective: **
_To proactively search for and identify potential persistence mechanisms that adversaries may use to maintain access to endpoints, servers, and network devices._

**Hypothesis:**
_Adversaries have established persistence mechanisms on endpoints, servers, or network devices to maintain access and control over the environment._

**Playbook:**

***1.	Define scope: Identify the network, endpoints, and servers that are in scope for this hunt. Ensure that the systems are up to date with the latest patches and have updated antivirus software.***

***2.	Gather data: Collect and analyze the following data sources to identify potential persistence mechanisms:***
*	_Endpoint logs (e.g., Windows event logs, system logs)_
*	_Network logs (e.g., firewall logs, DNS logs)_
*	_Application logs (e.g., web server logs, database logs)_
*	_Anti-virus logs and reports_

***3.	Develop queries: Develop and run queries across the collected data sources to identify any suspicious activities related to persistence. Queries may include:***
*	_Any new scheduled tasks or services created_
*	_Any registry changes related to persistence_
*	_Any changes to autorun entries or startup folders_
*	_Any changes to system files or directories that are commonly used for persistence_

***4.	Analyze results: Review the results of the queries to identify potential indicators of compromise (IOCs). These may include:***
 
*	_New scheduled tasks or services that are not associated with known applications or services_
*	_Suspicious registry keys or values_
*	_Changes to autorun entries or startup folders that are not authorized or expected_
*	_Any modifications to system files or directories that could indicate tampering_

***5.	Take action: Once potential IOCs have been identified, take the following actions:***
*	_Remove any suspicious persistence mechanisms_
*	_Conduct further investigation to confirm the existence of malicious activity_
*	_Update antivirus signatures and firewalls to block known malicious files and hashes_
*	_If necessary, escalate the incident to the incident response team for further action_

***6.	Report: Document the findings and actions taken during the hunt. Share the findings with the appropriate stakeholders and ensure that any necessary actions are taken to prevent future attacks.***

***By following this playbook, you can proactively identify potential persistence mechanisms and take steps to prevent further attacks on your network. It is important to conduct regular threat hunting exercises to stay ahead of potential attackers.***


