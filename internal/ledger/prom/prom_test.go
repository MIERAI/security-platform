package prom

import "testing"

func TestRender(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		series []Series
		want   string
	}{
		{"empty", nil, "\n"},
		{"families, labels, values", []Series{
			{Name: "security_sli", Labels: map[string]string{"sli": "a"}, Value: int64(3), Help: "Security SLI"},
			{Name: "security_sli", Labels: map[string]string{"sli": "b"}, Value: 13.96, Help: "Security SLI"},
			{Name: "security_x_total", Labels: map[string]string{"z": "1", "a": "q\"\\\n"}, Value: 1234567.0},
			{Name: "security_y", Value: 14.0, Help: "y"},
		}, "# HELP security_sli Security SLI\n# TYPE security_sli gauge\nsecurity_sli{sli=\"a\"} 3\n" +
			"security_sli{sli=\"b\"} 13.96\n# TYPE security_x_total counter\n" +
			"security_x_total{a=\"q'/ \",z=\"1\"} 1.23457e+06\n# HELP security_y y\n# TYPE security_y gauge\nsecurity_y 14\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := Render(tc.series); got != tc.want {
				t.Errorf("got\n%q\nwant\n%q", got, tc.want)
			}
		})
	}
}
