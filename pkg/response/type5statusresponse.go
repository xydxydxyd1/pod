package response

import (
	"encoding/hex"
)

type Type5StatusResponse struct {
	FaultEvent          uint8
	FaultEventTime      uint16
	Year                uint8
	Month               uint8
	Day                 uint8
	Hour                uint8
	Minute              uint8
}

// OFF 1  2  3  4 5  6 7 8 9 10111213 1415161718
// 02 11 05 PP QQQQ 00000000 00000000 MMDDYYHHMM

func (r *Type5StatusResponse) Marshal() ([]byte, error) {

	response, _ := hex.DecodeString("0211051c12c000000000000000000b1917100c")

	// Fault Code PP
	response[3] = r.FaultEvent

	// Fault Event Time QQQQ
	response[4] = uint8(r.FaultEventTime >> 8)
	response[5] = uint8(r.FaultEventTime & 0xff)

	// Activation date and time
	response[14] = r.Month  // MM
	response[15] = r.Day    // DD
	response[16] = r.Year   // YY
	response[17] = r.Hour   // HH
	response[18] = r.Minute // MM

	return response, nil
}
