package response

import (
	"encoding/hex"
)

type Type1StatusResponse struct {
	TriggeredAlerts [8]uint16
}

// CMD 1  2  3 4  5 6  7 8  910 1112 1314 1516 1718 1920
// 02 13 01 XXXX VVVV VVVV VVVV VVVV VVVV VVVV VVVV VVVV

func (r *Type1StatusResponse) Marshal() ([]byte, error) {

	response, _ := hex.DecodeString("021301000000000000000000000000000000000000")

	for i := 0; i < 8; i++ {
		response[(2 * i) + 5] = byte(r.TriggeredAlerts[i] >> 8)
		response[(2 * i) + 6] = byte(r.TriggeredAlerts[i] & 0xff)
	}
	return response, nil
}
