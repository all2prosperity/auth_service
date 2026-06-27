package services

import "testing"

func TestIsStrongPassword(t *testing.T) {
	ps := NewPasswordService()

	cases := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"valid", "Password1", false},
		{"too short", "Pass1", true},
		{"no uppercase", "password1", true},
		{"no lowercase", "PASSWORD1", true},
		{"no digit", "Password", true},
		{"too long", "Password1Password1Password1Password1", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ps.IsStrongPassword(tc.password)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error for %q, got nil", tc.password)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error for %q, got %v", tc.password, err)
			}
		})
	}
}
