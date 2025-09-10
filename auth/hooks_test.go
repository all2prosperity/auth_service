package auth

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegistrationHooks(t *testing.T) {
	t.Run("SetRegistrationHook", func(t *testing.T) {
		// Test setting hook after module creation
		module := &AuthModule{
			hooks: &AuthHooks{},
		}

		hookCalled := false
		testHook := func(ctx context.Context, user *UserRegistrationInfo) error {
			hookCalled = true
			assert.Equal(t, "test-user-123", user.UserID)
			assert.Equal(t, "sms_code", user.Method)
			t.Log("run test hook")
			return nil
		}

		module.SetRegistrationHook(testHook)
		assert.NotNil(t, module.GetRegistrationHook())

		// Simulate calling the hook
		userInfo := &UserRegistrationInfo{
			UserID:    "test-user-123",
			Method:    "sms_code",
			CreatedAt: time.Now(),
		}

		err := module.GetRegistrationHook()(context.Background(), userInfo)
		require.NoError(t, err)
		assert.True(t, hookCalled)
	})

	t.Run("SetHooks", func(t *testing.T) {
		module := &AuthModule{}

		hookCalled := false
		testHook := func(ctx context.Context, user *UserRegistrationInfo) error {
			hookCalled = true
			return nil
		}

		hooks := &AuthHooks{
			OnRegistered: testHook,
		}

		module.SetHooks(hooks)
		assert.Equal(t, hooks, module.hooks)

		// Test calling the hook
		userInfo := &UserRegistrationInfo{
			UserID: "test-user-456",
			Method: "email",
		}

		err := module.GetRegistrationHook()(context.Background(), userInfo)
		require.NoError(t, err)
		assert.True(t, hookCalled)
	})

	t.Run("NilHook", func(t *testing.T) {
		module := &AuthModule{
			hooks: &AuthHooks{},
		}

		// Should return nil when no hook is set
		assert.Nil(t, module.GetRegistrationHook())
	})

	t.Run("HooksInConfig", func(t *testing.T) {
		hookCalled := false
		testHook := func(ctx context.Context, user *UserRegistrationInfo) error {
			hookCalled = true
			assert.Equal(t, "config-user", user.UserID)
			return nil
		}

		hooks := &AuthHooks{
			OnRegistered: testHook,
		}

		// This tests the pattern used in NewAuthModule
		module := &AuthModule{}
		if hooks != nil {
			module.hooks = hooks
		} else {
			module.hooks = &AuthHooks{}
		}

		assert.NotNil(t, module.hooks.OnRegistered)

		// Simulate calling the hook
		userInfo := &UserRegistrationInfo{
			UserID: "config-user",
		}

		err := module.hooks.OnRegistered(context.Background(), userInfo)
		require.NoError(t, err)
		assert.True(t, hookCalled)
	})
}
