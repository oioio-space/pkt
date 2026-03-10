//go:build windows

package filter

// Layer constants (mirror of windivert.Layer, avoid import cycle).
const (
	layerNetwork        uint32 = 0
	layerNetworkForward uint32 = 1
	layerReflect        uint32 = 4
)

// Filter-flag bits sent in IOCTL_WINDIVERT_STARTUP (startup.flags).
// The driver uses these to decide which WFP callouts to register.
// Values from windivert_device.h.
const (
	FilterFlagInbound  uint64 = 0x0000000000000010
	FilterFlagOutbound uint64 = 0x0000000000000020
	FilterFlagIP       uint64 = 0x0000000000000040
	FilterFlagIPv6     uint64 = 0x0000000000000080
)

// Field IDs used internally by Analyze (from windivert_device.h).
const (
	fieldIDZero     uint32 = 0
	fieldIDInbound  uint32 = 1
	fieldIDOutbound uint32 = 2
	fieldIDIP       uint32 = 5
	fieldIDIPv6     uint32 = 6
)

// Analyze computes the startup.flags value for IOCTL_WINDIVERT_STARTUP.
// It replicates WinDivertAnalyzeFilter from windivert_helper.c:
// for each traffic category (inbound/outbound, IPv4/IPv6) it probes the
// filter with a synthetic packet and sets the flag if the filter can match.
// layer is the uint32 value of the windivert.Layer enum.
func Analyze(prog []FilterObject, layer uint32) uint64 {
	// False filter → no callouts needed.
	if !condExec(prog, fieldIDZero, 0) {
		return 0
	}

	var flags uint64

	if layer == layerNetwork || layer == layerNetworkForward {
		// Inbound: can the filter match a packet where inbound=1, outbound=0?
		if condExec(prog, fieldIDInbound, 1) && condExec(prog, fieldIDOutbound, 0) {
			flags |= FilterFlagInbound
		}
		// Outbound: can the filter match where outbound=1, inbound=0?
		if condExec(prog, fieldIDOutbound, 1) && condExec(prog, fieldIDInbound, 0) {
			flags |= FilterFlagOutbound
		}
	}

	if layer != layerReflect {
		// IPv4: can the filter match where ip=1, ipv6=0?
		if condExec(prog, fieldIDIP, 1) && condExec(prog, fieldIDIPv6, 0) {
			flags |= FilterFlagIP
		}
		// IPv6: can the filter match where ipv6=1, ip=0?
		if condExec(prog, fieldIDIPv6, 1) && condExec(prog, fieldIDIP, 0) {
			flags |= FilterFlagIPv6
		}
	}

	return flags
}

// condExec simulates filter execution assuming field == arg.
// Returns true if the filter CAN accept a packet with that field value
// (conservative: unknown jumps → true).
// Replicates WinDivertCondExecFilter from windivert_helper.c.
func condExec(prog []FilterObject, field uint32, arg uint32) bool {
	n := len(prog)
	if n == 0 {
		return true
	}

	result := make([]bool, n)

	for ip := n - 1; ip >= 0; ip-- {
		obj := prog[ip]

		resultSucc := resolveJump(obj.Success, ip, result, n)
		resultFail := resolveJump(obj.Failure, ip, result, n)

		switch {
		case resultSucc && resultFail:
			result[ip] = true
		case !resultSucc && !resultFail:
			result[ip] = false
		case obj.Field == field:
			// The field being probed is tested here.
			if obj.Neg != 0 || obj.Arg[1] != 0 || obj.Arg[2] != 0 || obj.Arg[3] != 0 {
				// Negated or multi-word arg → too complex to reason about, assume can match.
				result[ip] = true
			} else {
				var testResult bool
				switch obj.Test {
				case testEQ:
					testResult = arg == obj.Arg[0]
				case testNEQ:
					testResult = arg != obj.Arg[0]
				case testLT:
					testResult = arg < obj.Arg[0]
				case testLE:
					testResult = arg <= obj.Arg[0]
				case testGT:
					testResult = arg > obj.Arg[0]
				case testGE:
					testResult = arg >= obj.Arg[0]
				default:
					result[ip] = true
					continue
				}
				if testResult {
					result[ip] = resultSucc
				} else {
					result[ip] = resultFail
				}
			}
		default:
			// Different field → unknown contribution, assume can match.
			result[ip] = true
		}
	}

	return result[0]
}

// resolveJump converts a success/failure jump target to a bool.
func resolveJump(target uint16, ip int, result []bool, n int) bool {
	switch target {
	case 0x7FFE: // WINDIVERT_FILTER_RESULT_ACCEPT
		return true
	case 0x7FFF: // WINDIVERT_FILTER_RESULT_REJECT
		return false
	default:
		t := int(target)
		if t > ip && t < n {
			return result[t]
		}
		return true // unknown / forward ref → conservative
	}
}
