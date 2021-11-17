package command

import "testing"

func TestEnrollCall(t *testing.T) {
	err := Enroll("./msg", nil)
	if err != nil {
		t.Fatal(err)
	}
}
