rule Festi : driver
{
	meta:
		date		= "2012-12"
		maltype		= "Spam and DDoS bot"
		comment		= "Detects Win32/Rootkit.Festi driver binary"


  	strings: // All known Festi drivers contain these strings
    	$thebat			= "thebat.exe"
    	$opera			= "opera.exe"
    	$thunderbird	= "thunderbird.exe"
    	$telnet			= "telnet.exe"

	condition:
  		all of them
      	and uint32(uint32(0x3C)+8) > 1355097726 //PE_FILE_HEADER->TimeDateStamp = 50C5267E (10/12/2012 or later)
}