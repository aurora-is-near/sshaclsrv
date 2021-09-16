package acladmin

// func parseExpireTime(tS string) (time.Time, error) {
// 	switch len(tS) {
// 	case len(sshKeyExpireFormatShort):
// 		return time.Parse(sshKeyExpireFormatShort, tS)
// 	case len(sshKeyExpireFormatTime):
// 		return time.Parse(sshKeyExpireFormatTime, tS)
// 	case len(expireTimeFormat):
// 		return time.Parse(expireTimeFormat, tS)
// 	default:
// 		return time.Time{}, ErrInvalidExpire
// 	}
// }

// // KeyFingerPrint returns the SHA256 fingerprint of a key.
// func KeyFingerPrint(key string) (string, error) {
// 	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key))
// 	if err != nil {
// 		return "", err
// 	}
// 	return splitKey(ssh.FingerprintSHA256(pk)), nil
// }
//
// // AddKeyExpire adds key expiration time to the options.
// func AddKeyExpire(options []string, expire time.Time) []string {
// 	ret := make([]string, 1, 1+len(options))
// 	ret[0] = sshKeyExpireKey + expire.Format(expireTimeFormat)
// 	for _, o := range options {
// 		p := strings.ToLower(o)
// 		if !strings.HasPrefix(p, sshKeyExpireKey) {
// 			ret = append(ret, o)
// 		}
// 	}
// 	return ret
// }
//
// // AuthorizeKeyExpire checks key options for expiration time and returns it.
// func AuthorizeKeyExpire(keyOptions ...string) (time.Time, error) {
// 	var expire string
// 	for _, o := range keyOptions {
// 		p := strings.ToLower(o)
// 		if strings.HasPrefix(p, sshKeyExpireKey) {
// 			if expire != "" {
// 				return time.Time{}, ErrInvalidExpire
// 			}
// 			expire = p[matcherLen:]
// 		}
// 	}
// 	if expire != "" {
// 		return parseExpireTime(expire)
// 	}
// 	return time.Time{}, nil
// }
//
// func authorizedKeyExpired(key string) bool {
// 	_, _, keyOptions, _, err := ssh.ParseAuthorizedKey([]byte(key))
// 	if err != nil {
// 		return true
// 	}
// 	expireTime, err := AuthorizeKeyExpire(keyOptions...)
// 	if err != nil {
// 		return true
// 	}
// 	if !expireTime.IsZero() && expireTime.Before(time.Now()) {
// 		return true
// 	}
// 	return false
// }
