//go:build windows

package assets

import "golang.org/x/sys/windows"

func isPrivilegedUser() bool {
	token, err := openCurrentProcessToken()
	if err != nil {
		// Best-effort fallback; if we cannot query the token, default to non-privileged.
		return false
	}
	defer token.Close()

	if token.IsElevated() {
		return true
	}

	adminSid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err == nil {
		isMember, err := token.IsMember(adminSid)
		if err == nil && isMember {
			return true
		}
	}

	systemSid, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err == nil {
		if user, err := token.GetTokenUser(); err == nil && user != nil && user.User.Sid != nil {
			if windows.EqualSid(user.User.Sid, systemSid) {
				return true
			}
		}
	}

	return false
}

func openCurrentProcessToken() (windows.Token, error) {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return 0, err
	}
	return token, nil
}
