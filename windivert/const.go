//go:build windows

package windivert

// Layer definit le niveau d'interception WinDivert.
type Layer uint32

const (
	LayerNetwork        Layer = 0
	LayerNetworkForward Layer = 1
	LayerFlow           Layer = 2
	LayerSocket         Layer = 3
	LayerReflect        Layer = 4
)

// Flags pour Open().
const (
	FlagSniff     uint64 = 0x0001
	FlagDrop      uint64 = 0x0002
	FlagRecvOnly  uint64 = 0x0004
	FlagSendOnly  uint64 = 0x0008
	FlagNoInstall uint64 = 0x0010
	FlagFragments uint64 = 0x0020
)

// IOCTL function codes (parametre Function de CTL_CODE).
// CTL_CODE(DeviceType=0x12, Function, Method, Access)
// = (DeviceType<<16) | (Access<<14) | (Function<<2) | Method
// Source: windivert_device.h + imgk/divert-go
const (
	ioctlInitialize uint32 = 0x921 // METHOD_OUT_DIRECT, FILE_READ_DATA|FILE_WRITE_DATA
	ioctlStartup    uint32 = 0x922 // METHOD_IN_DIRECT,  FILE_READ_DATA|FILE_WRITE_DATA
	ioctlRecv       uint32 = 0x923 // METHOD_OUT_DIRECT, FILE_READ_DATA
	ioctlSend       uint32 = 0x924 // METHOD_IN_DIRECT,  FILE_READ_DATA|FILE_WRITE_DATA
	ioctlSetParam   uint32 = 0x925 // METHOD_IN_DIRECT,  FILE_READ_DATA|FILE_WRITE_DATA
	ioctlGetParam   uint32 = 0x926 // METHOD_OUT_DIRECT, FILE_READ_DATA
	ioctlShutdown   uint32 = 0x927 // METHOD_IN_DIRECT,  FILE_READ_DATA|FILE_WRITE_DATA
)

// ctlCode calcule un code IOCTL Windows complet.
func ctlCode(deviceType, function, method, access uint32) uint32 {
	return (deviceType << 16) | (access << 14) | (function << 2) | method
}

// Constantes CTL_CODE
const (
	fileDeviceNetwork = uint32(0x12)
	methodBuffered    = uint32(0)
	methodInDirect    = uint32(1)
	methodOutDirect   = uint32(2)
	fileReadData      = uint32(1)
	fileWriteData     = uint32(2)
)

// Codes IOCTL complets (calcules).
var (
	ioctlCodeInitialize = ctlCode(fileDeviceNetwork, ioctlInitialize, methodOutDirect, fileReadData|fileWriteData)
	ioctlCodeStartup    = ctlCode(fileDeviceNetwork, ioctlStartup, methodInDirect, fileReadData|fileWriteData)
	ioctlCodeRecv       = ctlCode(fileDeviceNetwork, ioctlRecv, methodOutDirect, fileReadData)
	ioctlCodeSend       = ctlCode(fileDeviceNetwork, ioctlSend, methodInDirect, fileReadData|fileWriteData)
	ioctlCodeShutdown   = ctlCode(fileDeviceNetwork, ioctlShutdown, methodInDirect, fileReadData|fileWriteData)
	ioctlCodeSetParam   = ctlCode(fileDeviceNetwork, ioctlSetParam, methodInDirect, fileReadData|fileWriteData)
	ioctlCodeGetParam   = ctlCode(fileDeviceNetwork, ioctlGetParam, methodOutDirect, fileReadData)
)

// priorityMax is the offset added to priority before passing to the driver.
// IOCTL priority = (int32(priority) + priorityMax), so range [0, 60000].
const priorityMax = int32(30000)

// Device path WinDivert 2.x.
const devicePath = `\.\WinDivert`

// Priority bounds.
const (
	PriorityHighest int16 = 30000
	PriorityLowest  int16 = -30000
	PriorityDefault int16 = 0
)
