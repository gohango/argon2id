package argon2id

import (
	"fmt"
	"testing"
)

func TestCompareHashAndPassword(t *testing.T) {
	type args struct {
		hash string
		pass []byte
	}
	tests := []struct {
		name        string
		args        args
		wantErr     bool
		expectedErr error
	}{
		{
			name: "Must yield to successful comparison",
			args: args{
				hash: "$argon2id$v=19$m=4096,t=3,p=1$82XldKYgqAqher7EuFzPNw$O1Epnr+m1JYkgtWcgVLID39ro6He105HTFnE+SinJyM",
				pass: []byte("foo123"),
			},
			wantErr:     false,
			expectedErr: nil,
		},
		{
			name: "Not an argon2id hash",
			args: args{
				hash: "$argon2i$v=19$m=4096,t=3,p=1$82XldKYgqAqher7EuFzPNw$O1Epnr+m1JYkgtWcgVLID39ro6He105HTFnE+SinJyM",
				pass: []byte("foo123"),
			},
			wantErr:     true,
			expectedErr: ErrIncompatibleVersion,
		},
		{
			name: "Invalid hash format",
			args: args{
				hash: "$argon2id$m=4096,t=3,p=1$82XldKYgqAqher7EuFzPNw$O1Epnr+m1JYkgtWcgVLID39ro6He105HTFnE+SinJyM",
				pass: []byte("foo123"),
			},
			wantErr:     true,
			expectedErr: ErrInvalidHash,
		},
		{
			name: "Passwords do not match",
			args: args{
				hash: "$argon2id$v=19$m=4096,t=3,p=1$82XldKYgqAqher7EuFzPNw$O1Epnr+m1JYkgtWcgVLID39ro6He105HTFnE+SinJym",
				pass: []byte("foo123"),
			},
			wantErr:     true,
			expectedErr: ErrPasswordNotMatch,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error = nil
			if err = CompareHashAndPassword(tt.args.hash, tt.args.pass); (err != nil) != tt.wantErr {
				t.Errorf("CompareHashAndPassword() error = %v, wantErr = %v", err, tt.wantErr)
			}

			if tt.wantErr && err != tt.expectedErr {
				t.Errorf("CompareHashAndPassword() error = %v, expectation = %v", err, tt.expectedErr)
			}
		})
	}
}

func TestGenerateFromPassword(t *testing.T) {
	type args struct {
		pass   []byte
		params *Params
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Corret password",
			args: args{
				pass: []byte("foo123"),
				params: &Params{
					Memory:      4096,
					Iterations:  1000,
					Parallelism: 0,
					SaltLength:  32,
					KeyLength:   64,
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			str, err := GenerateFromPassword(tt.args.pass, tt.args.params)
			fmt.Println(str)

			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateFromPassword() error = %v, wantErr = %v", err, tt.wantErr)
			}

			if err = CompareHashAndPassword(str, tt.args.pass); err != nil {
				t.Errorf("GenerateFromPassword() Failed to compare hashed password with the real password. %v.", err)
			}
		})
	}
}
