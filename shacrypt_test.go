package auth

import (
	"fmt"
	"testing"
)

func TestDissectSha(t *testing.T) {
	t.Parallel()
	type testData struct {
		secret string
		result bool
	}
	data := []testData{
		{"$5$qgB401R/ggz11Q5U$QAsQZuMF.xfkj7A0QrEvWpYgcStxtU8V3Wj5DSLOSI0", true},
		{"$5$rounds=5000$qgB401R/ggz11Q5U$QAsQZuMF.xfkj7A0QrEvWpYgcStxtU8V3Wj5DSLOSI0", true},
		{"$5$rounds=5000$foobar$qgB401R/ggz11Q5U$QAsQZuMF.xfkj7A0QrEvWpYgcStxtU8V3Wj5DSLOSI0", false},
		{"$5$QAsQZuMF.xfkj7A0QrEvWpYgcStxtU8V3Wj5DSLOSI0", false},
		{"$6$lseRR5fEdsK0sOkR$QTkArA5Z/arPmd78I7qmi8Wj/4bc8CbNw0FH59SYVXCfesr.AqOJINkGx/aaZ6gKYDbmYeFPSSMjMFW9HrMwR.", true},
		{"$6$rounds=5000$lseRR5fEdsK0sOkR$QTkArA5Z/arPmd78I7qmi8Wj/4bc8CbNw0FH59SYVXCfesr.AqOJINkGx/aaZ6gKYDbmYeFPSSMjMFW9HrMwR.", true},
		{"$6$rounds=5000$foobar$lseRR5fEdsK0sOkR$QTkArA5Z/arPmd78I7qmi8Wj/4bc8CbNw0FH59SYVXCfesr.AqOJINkGx/aaZ6gKYDbmYeFPSSMjMFW9HrMwR.", false},
		{"$6$QTkArA5Z/arPmd78I7qmi8Wj/4bc8CbNw0FH59SYVXCfesr.AqOJINkGx/aaZ6gKYDbmYeFPSSMjMFW9HrMwR.", false},
	}
	for i, tc := range data {
		t.Run(fmt.Sprintf("Vector%d", i), func(t *testing.T) {
			t.Parallel()
			_, err := DissectShaCryptHash([]byte(tc.secret))
			if !tc.result && err == nil {
				t.Error("DissectShaCrypthHash returned no error, want one")
				return
			}
			if tc.result && err != nil {
				t.Errorf("DissectShaCrypthHash returned error: %v, want none", err)
				return
			}
		})
	}
}
