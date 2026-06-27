package core_test

import (
	"context"
	"testing"
	"time"

	"github.com/all2prosperity/auth_service/core"
	"github.com/all2prosperity/auth_service/internal/testsupport"
	"github.com/all2prosperity/auth_service/models"
	"github.com/all2prosperity/auth_service/services"
)

const goodPassword = "GoodPass1"

func wantCode(t *testing.T, err *core.Error, code core.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error with code %v, got nil", code)
	}
	if err.Code != code {
		t.Fatalf("error code = %v (%s), want %v", err.Code, err.Message, code)
	}
}

func registerEmail(t *testing.T, c *core.AuthCore, email string) *core.AuthResult {
	t.Helper()
	res, err := c.Register(context.Background(), core.RegisterInput{Email: email, Password: goodPassword})
	if err != nil {
		t.Fatalf("register %s: %v", email, err.Message)
	}
	return res
}

// --- Register ---

func TestRegister(t *testing.T) {
	d := testsupport.NewCore(t)
	ctx := context.Background()

	t.Run("email success, unconfirmed", func(t *testing.T) {
		res := registerEmail(t, d.Core, "reg1@example.com")
		if res.User.UserID == "" || res.Tokens.AccessToken == "" || res.Tokens.RefreshToken == "" {
			t.Fatal("expected user id and tokens")
		}
		var u models.User
		testsupport.RawDB(d.DB).Where("email = ?", "reg1@example.com").First(&u)
		if u.ConfirmedAt != nil {
			t.Fatal("email registration should not be auto-confirmed")
		}
	})

	t.Run("phone success, confirmed", func(t *testing.T) {
		res, err := d.Core.Register(ctx, core.RegisterInput{Phone: "+8613800001000", Password: goodPassword})
		if err != nil {
			t.Fatalf("register phone: %v", err.Message)
		}
		var u models.User
		testsupport.RawDB(d.DB).Where("id = ?", res.User.UserID).First(&u)
		if u.ConfirmedAt == nil {
			t.Fatal("phone registration should be auto-confirmed")
		}
	})

	t.Run("weak password", func(t *testing.T) {
		_, err := d.Core.Register(ctx, core.RegisterInput{Email: "weak@example.com", Password: "weak"})
		wantCode(t, err, core.CodeInvalidArgument)
	})

	t.Run("duplicate", func(t *testing.T) {
		registerEmail(t, d.Core, "dup@example.com")
		_, err := d.Core.Register(ctx, core.RegisterInput{Email: "dup@example.com", Password: goodPassword})
		wantCode(t, err, core.CodeAlreadyExists)
	})

	t.Run("both identifiers", func(t *testing.T) {
		_, err := d.Core.Register(ctx, core.RegisterInput{Email: "a@example.com", Phone: "+8613800002000", Password: goodPassword})
		wantCode(t, err, core.CodeInvalidArgument)
	})

	t.Run("no identifier", func(t *testing.T) {
		_, err := d.Core.Register(ctx, core.RegisterInput{Password: goodPassword})
		wantCode(t, err, core.CodeInvalidArgument)
	})
}

// --- Login ---

func TestLogin(t *testing.T) {
	d := testsupport.NewCore(t)
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		registerEmail(t, d.Core, "login@example.com")
		res, err := d.Core.Login(ctx, core.LoginInput{Email: "login@example.com", Password: goodPassword, IP: "1.1.1.1"})
		if err != nil {
			t.Fatalf("login: %v", err.Message)
		}
		if res.Tokens.AccessToken == "" {
			t.Fatal("expected access token")
		}
	})

	t.Run("wrong password unauthenticated", func(t *testing.T) {
		registerEmail(t, d.Core, "wp@example.com")
		_, err := d.Core.Login(ctx, core.LoginInput{Email: "wp@example.com", Password: "WrongPass1", IP: "2.2.2.2"})
		wantCode(t, err, core.CodeUnauthenticated)
	})

	t.Run("brute force locks out", func(t *testing.T) {
		registerEmail(t, d.Core, "bf@example.com")
		ip := "3.3.3.3"
		// Security.LoginMaxAttempts = 3
		for i := 0; i < 3; i++ {
			_, err := d.Core.Login(ctx, core.LoginInput{Email: "bf@example.com", Password: "WrongPass1", IP: ip})
			wantCode(t, err, core.CodeUnauthenticated)
		}
		// Now locked: even the correct password is rejected with 429-equivalent.
		_, err := d.Core.Login(ctx, core.LoginInput{Email: "bf@example.com", Password: goodPassword, IP: ip})
		wantCode(t, err, core.CodeResourceExhausted)
	})

	t.Run("locked user permission denied", func(t *testing.T) {
		res := registerEmail(t, d.Core, "locked@example.com")
		future := time.Now().Add(time.Hour)
		testsupport.RawDB(d.DB).Model(&models.User{}).Where("id = ?", res.User.UserID).Update("locked_until", future)
		_, err := d.Core.Login(ctx, core.LoginInput{Email: "locked@example.com", Password: goodPassword, IP: "4.4.4.4"})
		wantCode(t, err, core.CodePermissionDenied)
	})

	t.Run("success resets attempts", func(t *testing.T) {
		registerEmail(t, d.Core, "reset@example.com")
		ip := "5.5.5.5"
		// Two failures (below the lock threshold), then a success.
		for i := 0; i < 2; i++ {
			d.Core.Login(ctx, core.LoginInput{Email: "reset@example.com", Password: "WrongPass1", IP: ip})
		}
		if _, err := d.Core.Login(ctx, core.LoginInput{Email: "reset@example.com", Password: goodPassword, IP: ip}); err != nil {
			t.Fatalf("login after partial failures: %v", err.Message)
		}
		var count int64
		testsupport.RawDB(d.DB).Model(&models.LoginAttempt{}).Where("identifier = ? AND ip = ?", "reset@example.com", ip).Count(&count)
		if count != 0 {
			t.Fatalf("login attempts should be reset after success, found %d", count)
		}
	})
}

// --- RefreshToken ---

func TestRefreshToken(t *testing.T) {
	d := testsupport.NewCore(t)
	ctx := context.Background()

	t.Run("success rotates", func(t *testing.T) {
		res := registerEmail(t, d.Core, "rt@example.com")
		pair, err := d.Core.RefreshToken(ctx, core.RefreshInput{RefreshToken: res.Tokens.RefreshToken})
		if err != nil {
			t.Fatalf("refresh: %v", err.Message)
		}
		if pair.AccessToken == "" || pair.RefreshToken == "" {
			t.Fatal("expected rotated token pair")
		}
	})

	t.Run("invalid token", func(t *testing.T) {
		_, err := d.Core.RefreshToken(ctx, core.RefreshInput{RefreshToken: "not-a-token"})
		wantCode(t, err, core.CodeUnauthenticated)
	})

	t.Run("reused refresh rejected", func(t *testing.T) {
		res := registerEmail(t, d.Core, "reuse@example.com")
		old := res.Tokens.RefreshToken
		if _, err := d.Core.RefreshToken(ctx, core.RefreshInput{RefreshToken: old}); err != nil {
			t.Fatalf("first refresh: %v", err.Message)
		}
		_, err := d.Core.RefreshToken(ctx, core.RefreshInput{RefreshToken: old})
		wantCode(t, err, core.CodeUnauthenticated)
	})
}

// --- Logout / GetMe ---

func TestLogoutAndGetMe(t *testing.T) {
	d := testsupport.NewCore(t)
	ctx := context.Background()

	res := registerEmail(t, d.Core, "me@example.com")
	claims, err := d.JWT.ValidateAccessToken(res.Tokens.AccessToken)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	authedCtx := services.WithClaims(ctx, claims)

	t.Run("getme with claims", func(t *testing.T) {
		info, cerr := d.Core.GetMe(authedCtx)
		if cerr != nil || info.UserID != res.User.UserID {
			t.Fatalf("getme: info=%v err=%v", info, cerr)
		}
	})

	t.Run("getme without claims", func(t *testing.T) {
		_, cerr := d.Core.GetMe(ctx)
		wantCode(t, cerr, core.CodeUnauthenticated)
	})

	t.Run("logout revokes token", func(t *testing.T) {
		if cerr := d.Core.Logout(authedCtx); cerr != nil {
			t.Fatalf("logout: %v", cerr.Message)
		}
		if !d.Blacklist.IsRevoked(ctx, claims.ID, claims.UserID, claims.Epoch) {
			t.Fatal("token should be revoked after logout")
		}
	})
}

// --- Code login / register (using the gated test bypass code) ---

func TestCodeFlows(t *testing.T) {
	d := testsupport.NewCore(t)
	ctx := context.Background()
	const bypass = "159357" // enabled in testsupport.NewSecurity

	t.Run("code login creates user", func(t *testing.T) {
		res, err := d.Core.CompleteCodeLogin(ctx, core.CompleteCodeLoginInput{Email: "codelogin@example.com", Code: bypass})
		if err != nil {
			t.Fatalf("code login: %v", err.Message)
		}
		if res.User.UserID == "" {
			t.Fatal("expected a user to be created")
		}
	})

	t.Run("code login wrong code", func(t *testing.T) {
		_, err := d.Core.CompleteCodeLogin(ctx, core.CompleteCodeLoginInput{Email: "x@example.com", Code: "000000"})
		wantCode(t, err, core.CodeUnauthenticated)
	})

	t.Run("code register creates user", func(t *testing.T) {
		res, err := d.Core.CompleteCodeRegister(ctx, core.CompleteCodeRegisterInput{Phone: "+8613800003000", Code: bypass, Password: goodPassword})
		if err != nil {
			t.Fatalf("code register: %v", err.Message)
		}
		if res.User.UserID == "" {
			t.Fatal("expected a user to be created")
		}
	})

	t.Run("code register weak password", func(t *testing.T) {
		_, err := d.Core.CompleteCodeRegister(ctx, core.CompleteCodeRegisterInput{Phone: "+8613800004000", Code: bypass, Password: "weak"})
		wantCode(t, err, core.CodeInvalidArgument)
	})

	t.Run("code register duplicate phone", func(t *testing.T) {
		phone := "+8613800005000"
		if _, err := d.Core.CompleteCodeRegister(ctx, core.CompleteCodeRegisterInput{Phone: phone, Code: bypass, Password: goodPassword}); err != nil {
			t.Fatalf("first register: %v", err.Message)
		}
		_, err := d.Core.CompleteCodeRegister(ctx, core.CompleteCodeRegisterInput{Phone: phone, Code: bypass, Password: goodPassword})
		wantCode(t, err, core.CodeAlreadyExists)
	})
}

// --- Start* code senders (SMTP/SMS unconfigured → skip path) ---

func TestStartCodeSenders(t *testing.T) {
	d := testsupport.NewCore(t)
	ctx := context.Background()

	if err := d.Core.StartCodeLogin(ctx, core.IdentifierInput{Email: "start@example.com"}); err != nil {
		t.Fatalf("start code login: %v", err.Message)
	}
	if err := d.Core.StartPasswordReset(ctx, core.IdentifierInput{Email: "start2@example.com"}); err != nil {
		t.Fatalf("start password reset: %v", err.Message)
	}
}
