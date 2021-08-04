# BypassETW_CSharp

Blog link: working on it 

- A simple Project to Bypass ETW
- Load the ntdll.dll with LoadLibrary And then Get the Function(RtlInitializeResource)'s address via GetProcAddress.
- ~~With the correct offset, the ”RtlInitializeResource“ address, and patch bytes, you should be able to patch it~~
	- ~~**one thing you need to is, the offset on a different system(like a different version of win10) is different.**~~
	- ~~**So it may not gonna works on other systems.**~~
	- ~~**I only tested in Win10, and here is the windows version below.**~~
	```
	10.0.19042
	```
- I really don't think using the offset is a good idea.
- I am gonna update the project later with the egg hunt.（DONE）
- ** I updated the code，now it using egg hunt in steal of offset.**__20210804


## Usage
1. Launch through some white-list applications
	* Without ETW bypass.
	![avatar](https://raw.githubusercontent.com/Kara-4search/tempPic/main/Without_BypassETW.png)
	* With ETW bypass.
	![avatar](https://raw.githubusercontent.com/Kara-4search/tempPic/main/With_BypassETW.png)
2. Combining with other shellcode loader or technic like
	* bypass AMSI (Coming soon)
	* bypass Sysmon&EventLogs (https://github.com/Kara-4search/WindowsEventLogsBypass_Csharp)
	* PPIP&Commandline Spoofing (https://github.com/Kara-4search/PEB-PPIDspoofing_Csharp)


	
## TO-DO list
- bypass some AVs
- Update the project later with the egg hunt（DONE）
- Build a shellcode loader combine all the technics
	
## Reference link:
	1. https://blog.securityevaluators.com/creating-av-resistant-malware-part-1-7604b83ea0c0
	2. https://blog.securityevaluators.com/creating-av-resistant-malware-part-2-1ba1784064bc
	3. https://blog.securityevaluators.com/creating-av-resistant-malware-part-3-fdacdf071a5f
	4. https://blog.securityevaluators.com/creating-av-resistant-malware-part-4-6cb2d215a50f
	5. https://blog.xpnsec.com/hiding-your-dotnet-etw/
	6. https://idiotc4t.com/defense-evasion/memory-pacth-bypass-etw
	7. http://www.hackdig.com/03/hack-73606.htm
	8. https://www.mdsec.co.uk/2020/03/hiding-your-net-etw/