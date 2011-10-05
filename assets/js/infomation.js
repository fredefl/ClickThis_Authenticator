function DeviceInfomation(){
	document.addEventListener("deviceready", Device, false);	
}
//Get Device Information
function Device(){      
	var PhoneName = device.name;
	var PhoneGap = device.phonegap;
	var PhonePlatform = device.platform;
	var UUID = device.uuid;
	var OSVersion = device.version;
}