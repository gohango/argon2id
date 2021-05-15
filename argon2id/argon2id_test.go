package argon2id

import "testing"

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
			wantErr: false,
			expectedErr: nil,
		},
		{
			name: "Not an argon2id hash",
			args: args{
				hash: "$argon2i$v=19$m=4096,t=3,p=1$82XldKYgqAqher7EuFzPNw$O1Epnr+m1JYkgtWcgVLID39ro6He105HTFnE+SinJyM",
				pass: []byte("foo123"),
			},
			wantErr: true,
			expectedErr: ErrIncompatibleVersion,
		},
		{
			name: "Invalid hash format",
			args: args{
				hash: "$argon2id$m=4096,t=3,p=1$82XldKYgqAqher7EuFzPNw$O1Epnr+m1JYkgtWcgVLID39ro6He105HTFnE+SinJyM",
				pass: []byte("foo123"),
			},
			wantErr: true,
			expectedErr: ErrInvalidHash,
		},
		{
			name: "Passwords do not match",
			args: args{
				hash: "$argon2id$v=19$m=4096,t=3,p=1$82XldKYgqAqher7EuFzPNw$O1Epnr+m1JYkgtWcgVLID39ro6He105HTFnE+SinJym",
				pass: []byte("foo123"),
			},
			wantErr: true,
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
