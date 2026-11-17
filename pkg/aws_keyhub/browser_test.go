package aws_keyhub

import (
	"reflect"
	"testing"
)

func TestBuildBrowserCommand(t *testing.T) {
	const link = "https://keyhub.example.com/login?code=ABC"
	tests := []struct {
		name       string
		configured []string
		want       []string
	}{
		{"nil", nil, nil},
		{"empty", []string{}, nil},
		{"blank executable", []string{" "}, nil},
		{"appends link without placeholder", []string{"firefox", "-P", "work"}, []string{"firefox", "-P", "work", link}},
		{"replaces placeholder", []string{"firefox", "--new-window", "{url}"}, []string{"firefox", "--new-window", link}},
		{"replaces embedded placeholder", []string{"browser", "--app={url}"}, []string{"browser", "--app=" + link}},
		{
			"keeps spaces in executable",
			[]string{`C:\Program Files\Mozilla Firefox\firefox.exe`, "-P", "work", "{url}"},
			[]string{`C:\Program Files\Mozilla Firefox\firefox.exe`, "-P", "work", link},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orig := append([]string(nil), tt.configured...)
			if got := buildBrowserCommand(tt.configured, link); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %q, want %q", got, tt.want)
			}
			if !reflect.DeepEqual(append([]string(nil), tt.configured...), orig) {
				t.Errorf("configured command was modified: %q", tt.configured)
			}
		})
	}
}
