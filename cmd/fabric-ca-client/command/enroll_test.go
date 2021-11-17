package command

import "testing"

func TestEnrollCall(t *testing.T) {
	err := Enroll("http://admin:adminpw@localhost:7054", "./msg", "one.pem", "", "")
	if err != nil {
		t.Fatal(err)
	}
}
