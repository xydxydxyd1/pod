package response

import (
	"encoding/hex"
)

type Type3StatusResponse struct {
	FaultEvent          uint8
	FaultEventTime      uint16
	MinutesActive       uint16
}

// OFF 1  2  3  4 5  6 7  8  9 10
// 02 LL 03 PP QQQQ SSSS 04 3c XXXXXXXX ...

func (r *Type3StatusResponse) Marshal() ([]byte, error) {
	response, _ := hex.DecodeString("02f8030000000d4c043c287331002d733b003072320035733b00387232003d733b004072320045723d00487232004d723c005072330055723e00587235805d733d806073348001713e800450338009503c800c50338011513b801475328019723a801c72328021723b002472330029733f002c7334003172400034723500397240003c733400417241004473340049733e004c73330051733d005473330059733f805c73348061713e800074338005723d80087233800d723d801073338015733c80187334801d723d802073340025724000287336002d7241003072370035734100387337003d7243004072380045724400487238004d714300")

	// Fault PP
	response[3] = r.FaultEvent

	// Fault Time QQQQ
	response[4] = byte(r.FaultEventTime >> 8)
	response[5] = byte(r.FaultEventTime & 0xff)

	// Minutes Since Activation SSSS
	response[6] = byte(r.MinutesActive >> 8)
	response[7] = byte(r.MinutesActive & 0xff)

	return response, nil
}
