import wmi
import sys
import argparse
import sys

parser = argparse.ArgumentParser(prog="WMIScan",description='WMI Scanner v1.0.')

parser.add_argument("-ip",dest="ip",help="specify a remote IP.")
parser.add_argument("-u",dest="user", help="specify a username.")
parser.add_argument("-p",dest="password",help="specify a password.")
parser.add_argument("--version", action="version", version="%(prog)s 1.0")

args = parser.parse_args()

if args.ip is None and args.user is None and args.password is None:
	try:
		c=wmi.WMI("localhost")
	except wmi.x_wmi, x:
		print x.com_error
elif args.ip is not None and args.user is None and args.password is None:
	try:
		c=wmi.WMI(args.ip)
	except wmi.x_wmi, x:
		print x.com_error
		sys.exit(-1)
else:
	try:
		connection = wmi.connect_server (
		server=args.ip,
		user=args.user,
		password=args.password
		)
		c=wmi.WMI(wmi=connection)
	except Exception, e:
		print e
		sys.exit(-1)

print "-= Operating System Information =-"
for os in c.Win32_OperatingSystem():
    print "Name:",os.name
    print "CName:",os.csname
    print "Manufacturer:",os.Manufacturer
    print "Build Number:",os.buildnumber
    print "Boot Device:",os.bootdevice
    print "Version:",os.version
    print "Win Directory:",os.windowsdirectory
    print "System Directory:",os.systemdirectory
    print "Architecture:",os.OSArchitecture
print "\n"

print "-= Network Adapter Configuration =-"
for netif in c.Win32_NetworkAdapterConfiguration():
	print netif.Caption, netif.IPAddress, netif.IPSubnet, netif.DefaultIPGateway, netif.DHCPServer, netif.DNSDomain, netif.ServiceName
print "\n"

print "-= Routing Table =-"
routetempl = "%-30s %-30s %-30s"
print (routetempl % ("Network Destination", "Netmask", "Gateway"))
for desc in c.Win32_IP4RouteTable():
	print (routetempl%(desc.Destination, desc.Mask,desc.NextHop))
print "\n"

print "-= List of Groups & Users =-"
for group in c.Win32_Group():
	print group.Caption
	for user in group.associators("Win32_GroupUser"):
		print "\t", user.Caption
print "\n"

print "-= List of Shared Drives =-"
for share in c.Win32_Share ():
	print "Name:", share.Name,"Path:",share.Path
print "\n"

print "\n"

print "-= List of Startup Commands =-"
for command in c.Win32_StartupCommand():
	print "Name: ", command.Properties_('Caption').Value
	print "Command: ", command.Properties_('Command').Value
	print "Description: ", command.Properties_('Description').Value
	print "Location: ", command.Properties_('Location').Value
	print "User: ", command.Properties_('User').Value
print "\n"

print "-= List of User Profile =-"

profiles=[]
for up in c.Win32_UserProfile():
    profiles.append((up.LastUseTime, up.SID, up.LocalPath))
profiles.sort(reverse=True)
for p in profiles:
    print p
print "\n"

print "-= List of User Accounts =-"
for ua in c.Win32_UserAccount():
    print "Account Name:",ua.caption, "Lockout:", ua.lockout, "PasswordChangeable:", ua.PasswordChangeable,"PasswordExpires:",ua.PasswordExpires
print "\n"

print "-= List of Logon Users =-"
for us in c.Win32_LogonSession():
    try:
        for user in us.references("Win32_LoggedOnUser"):
			#print user.Antecedent.Caption, user.Antecedent.SID
            print user.Properties_('Antecedent').Value
    except:
		pass
print "\n"

print "-= List of Installed Software =-"
for s in c.Win32_Product():
	print s.Name.encode('utf-8'), s.Version

print "\n"
print "-= List of Services =-"
servtempl = "%-30s %-30s %-30s %-30s"
print (servtempl % ("ServiceName", "RunAs", "State", "PathName"))
print "\n"
for service in c.Win32_Service():
	#if service.Properties_('ProcessId').Value>0:
	print (servtempl%(service.Properties_('Name').Value,
	service.Properties_('StartName').Value,
	service.Properties_('State').Value,
	service.Properties_('PathName').Value,
	))
print "\n"

print "-= List of Processes =-"
noproc=c.Win32_Process()
print "Number of Processes found: "+str(len(noproc))
templ = "%-30s %-30s %-30s %-30s"#" %-13s %-6s %s"
print (templ % ("Process ID","Process Name", "Process Owner","Executable Path"))
print "\n"
for proc in c.Win32_Process():
	if proc.ProcessId>0 and proc.GetOwner()[2]!=None:
		print (templ%(proc.ProcessId,proc.Name,proc.GetOwner()[2],proc.ExecutablePath))
print "\n"


